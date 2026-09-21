# -*- coding: utf-8 -*-
"""Orchestration for the ``pack`` and ``unpack`` verbs.

Enumerate the source, record every item in the SQLite catalog, run the per-item
transform across a process pool, then move the staged result to the destination.
Directories and symlinks are carried as catalog metadata so an unpacked tree
round-trips byte-for-byte (permissions, mtimes, empty dirs and links included).
"""

import os
import json
import shutil
import logging
from concurrent.futures import ProcessPoolExecutor

from .. import __version__
from . import codecs, transport
from .catalog import Catalog
from .crypto import LocalCryptor
from .fs import source_fs
from .naming import cipher_name, parse_cipher_name
from .pipeline import pack_item, unpack_item, _restore_meta

LOG = logging.getLogger(__name__)

CATALOG_NAME = 'catalog.sqlite'
DEFAULT_WORKDIR = os.environ.get('C4GH_WORKDIR', os.path.join(os.getcwd(), 'crypt4gh-work'))


def _default_jobs(jobs):
    if jobs and jobs > 0:
        return jobs
    return min(os.cpu_count() or 1, 8)


def _run_pool(func, jobs, njobs):
    """Map ``func`` over ``jobs``; run inline when njobs==1 (easier to debug)."""
    if not jobs:
        return []
    if njobs == 1:
        return [func(j) for j in jobs]
    with ProcessPoolExecutor(max_workers=njobs) as pool:
        return list(pool.map(func, jobs))


def _preflight_workdir(working):
    os.makedirs(working, exist_ok=True)
    try:
        free = shutil.disk_usage(working).free
        LOG.info('Working dir %s: %.1f GiB free (must hold the full staged set)',
                 working, free / 2**30)
    except OSError:
        pass


# ----------------------------------------------------------------------
# pack
# ----------------------------------------------------------------------
def pack(source, dest, *, seckey, recipient_pubkeys, tar=False, compress='none',
         working_dir=None, jobs=None, sender_pubkey=None):
    """Encrypt a source tree into a destination tree.

    :returns: a summary dict (``done``/``error`` counts and byte totals).
    """
    src = transport.parse_endpoint(source)
    dst = transport.parse_endpoint(dest)
    if src.is_remote and dst.is_remote:
        raise ValueError('At most one of source/destination may be remote (like rsync)')

    codec_name, codec_level = codecs.parse_codec(compress)
    if codec_name != 'none' and not tar:
        raise ValueError('--compress requires --tar (compression happens between tar and encryption)')
    codecs.ensure_available(codec_name)
    recipient_pubkeys = list(recipient_pubkeys)
    if not recipient_pubkeys:
        raise ValueError('At least one recipient public key is required')

    # Stage straight into a local destination; otherwise into a working dir.
    if working_dir:
        working = os.path.abspath(working_dir)
    elif dst.kind == 'local':
        working = dst.path
    else:
        working = os.path.abspath(DEFAULT_WORKDIR)
    _preflight_workdir(working)

    fs = source_fs(src)
    if not fs.exists():
        raise ValueError(f'Source directory not found: {src}')

    options = {
        'tar': tar, 'compress': f'{codec_name}:{codec_level}' if codec_level else codec_name,
        'recipients': [pk.hex() for pk in recipient_pubkeys],
    }
    catalog = Catalog(os.path.join(working, CATALOG_NAME))
    run_id = catalog.start_run('pack', str(src), str(dst), options, __version__)

    # -- enumerate + record ------------------------------------------------
    encryptable = []
    for entry in _enumerate_pack(fs, tar, codec_name, codec_level):
        if entry['kind'] in ('file', 'tar'):
            entry['cipher_relpath'] = cipher_name(entry['relpath'], entry['kind'],
                                                  entry.get('codec', 'none'))
            entry['status'] = 'pending'
            encryptable.append(entry)
        else:
            entry['status'] = 'done'  # dir / symlink: metadata only
        catalog.add_item(run_id, entry)

    # -- transform ---------------------------------------------------------
    cryptor = LocalCryptor(seckey, recipient_pubkeys, sender_pubkey)
    njobs = _default_jobs(jobs)
    LOG.info('Packing %d item(s) with %d worker(s)', len(encryptable), njobs)
    jobs_list = [{'entry': e, 'source_endpoint': src, 'working_dir': working, 'cryptor': cryptor}
                 for e in encryptable]
    results = _run_pool(pack_item, jobs_list, njobs)

    for r in results:
        catalog.finish_item(run_id, r['relpath'], status=r['status'], error=r.get('error'),
                            src_sha256=r.get('src_sha256'), src_size=r.get('src_size'),
                            cipher_size=r.get('cipher_size'), cipher_sha256=r.get('cipher_sha256'))

    summary = _summarize(catalog, run_id)
    catalog.close()

    # -- transport ---------------------------------------------------------
    if dst.is_remote or (dst.kind == 'local' and os.path.abspath(dst.path) != working):
        LOG.info('Pushing staged ciphertext to %s', dst)
        transport.push(working, dst)

    _raise_on_failures(summary, 'pack')
    return summary


def _enumerate_pack(fs, tar, codec_name, codec_level):
    if not tar:
        # Mirror mode: every file/dir/symlink, recursively.
        yield from fs.walk()
        return
    # Tar mode: each top-level subdirectory becomes one tarball; loose files and
    # symlinks at the root are handled individually.
    for entry in fs.children():
        if entry['kind'] == 'dir':
            yield {'relpath': entry['relpath'], 'kind': 'tar',
                   'codec': codec_name, 'codec_level': codec_level,
                   'src_mode': None, 'src_mtime': None, 'src_size': None,
                   'symlink_target': None}
        else:
            yield entry


# ----------------------------------------------------------------------
# unpack
# ----------------------------------------------------------------------
def unpack(source, dest, *, seckey, sender_pubkey=None, working_dir=None, jobs=None):
    """Decrypt a ciphertext tree into a plaintext tree."""
    src = transport.parse_endpoint(source)
    dst = transport.parse_endpoint(dest)
    if src.is_remote and dst.is_remote:
        raise ValueError('At most one of source/destination may be remote (like rsync)')

    working = os.path.abspath(working_dir) if working_dir else os.path.abspath(DEFAULT_WORKDIR)

    # Locate the ciphertext (pull it local if the source is remote).
    if src.kind == 'local':
        cipher_dir = src.path
    else:
        _preflight_workdir(working)
        cipher_dir = os.path.join(working, 'ciphertext')
        LOG.info('Pulling ciphertext from %s', src)
        transport.pull(src, cipher_dir)

    # Output straight into a local dest; otherwise stage then push.
    if dst.kind == 'local':
        out_root = dst.path
    else:
        out_root = os.path.join(working, 'plaintext')
    os.makedirs(out_root, exist_ok=True)

    catalog, run_id, items = _load_unpack_items(cipher_dir)

    # Create empty dirs and symlinks first (shallow -> deep).
    _prepare_tree(out_root, items)

    encryptable = [it for it in items if it['kind'] in ('file', 'tar')]
    cryptor = LocalCryptor(seckey, (), sender_pubkey)
    njobs = _default_jobs(jobs)
    LOG.info('Unpacking %d item(s) with %d worker(s)', len(encryptable), njobs)
    jobs_list = [{'item': it, 'cipher_path': os.path.join(cipher_dir, it['cipher_relpath']),
                  'out_root': out_root, 'cryptor': cryptor} for it in encryptable]
    results = _run_pool(unpack_item, jobs_list, njobs)

    if catalog:
        for r in results:
            catalog.finish_item(run_id, r['relpath'], status=r['status'], error=r.get('error'))

    # Restore directory permissions/mtimes last (deep -> shallow).
    _finalize_tree(out_root, items)

    summary = {'done': sum(r['status'] == 'done' for r in results),
               'error': sum(r['status'] == 'error' for r in results),
               'errors': [(r['relpath'], r['error']) for r in results if r['status'] == 'error']}
    if catalog:
        catalog.close()

    if dst.is_remote:
        LOG.info('Pushing plaintext to %s', dst)
        transport.push(out_root, dst)

    _raise_on_failures(summary, 'unpack')
    return summary


def _load_unpack_items(cipher_dir):
    """Prefer the catalog; fall back to scanning for *.c4gh files."""
    cat_path = os.path.join(cipher_dir, CATALOG_NAME)
    if os.path.exists(cat_path):
        catalog = Catalog(cat_path)
        run = catalog.latest_run('pack')
        if run:
            return catalog, run['id'], catalog.items(run['id'])
        catalog.close()

    LOG.warning('No catalog found in %s; reconstructing from filenames only '
                '(empty dirs, symlinks and permissions will not be restored)', cipher_dir)
    items = []
    for dirpath, _dirs, files in os.walk(cipher_dir):
        for f in files:
            if not f.endswith('.c4gh'):
                continue
            cipher_relpath = os.path.relpath(os.path.join(dirpath, f), cipher_dir)
            relpath, kind, codec = parse_cipher_name(cipher_relpath)
            items.append({'relpath': relpath, 'kind': kind, 'codec': codec,
                          'cipher_relpath': cipher_relpath, 'src_sha256': None,
                          'src_mode': None, 'src_mtime': None, 'symlink_target': None})
    return None, None, items


def _prepare_tree(out_root, items):
    for it in sorted((i for i in items if i['kind'] == 'dir'),
                     key=lambda i: i['relpath'].count('/')):
        os.makedirs(os.path.join(out_root, it['relpath']), exist_ok=True)
    for it in (i for i in items if i['kind'] == 'symlink'):
        link = os.path.join(out_root, it['relpath'])
        os.makedirs(os.path.dirname(link) or '.', exist_ok=True)
        if os.path.lexists(link):
            os.remove(link)
        os.symlink(it['symlink_target'], link)
        _restore_meta(link, it, follow_symlinks=False)


def _finalize_tree(out_root, items):
    # Deepest first so setting a parent's mtime is not disturbed by child writes.
    for it in sorted((i for i in items if i['kind'] == 'dir'),
                     key=lambda i: i['relpath'].count('/'), reverse=True):
        _restore_meta(os.path.join(out_root, it['relpath']), it)


# ----------------------------------------------------------------------
def _summarize(catalog, run_id):
    counts = catalog.counts(run_id)
    errors = [(it['relpath'], it['error']) for it in catalog.items(run_id, status='error')]
    return {'done': counts.get('done', 0), 'error': counts.get('error', 0), 'errors': errors}


def _raise_on_failures(summary, verb):
    if summary.get('error'):
        first = summary['errors'][0] if summary.get('errors') else ('?', 'unknown')
        raise ValueError(f'{verb}: {summary["error"]} item(s) failed; first: {first[0]}: {first[1]}')
