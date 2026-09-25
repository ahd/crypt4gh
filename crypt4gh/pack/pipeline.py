# -*- coding: utf-8 -*-
"""Per-item transform: the streaming heart of pack/unpack.

Each *item* is one file or one tarred subdirectory.  These functions are the
unit of work handed to the process pool, so they take plain, picklable
arguments and return a plain result dict.

Pack:   source --> [tar] --> [compress] --> encrypt --> working/<cipher>
Unpack: working/<cipher> --> decrypt --> [decompress] --> [untar] --> dest

The plaintext that crypt4gh actually sees (the file bytes, or the compressed-tar
byte stream) is SHA-256'd inline on both legs, so unpack can verify it restores
exactly what pack encrypted.
"""

import os
import stat
import logging
import subprocess

from .streams import HashingReader, HashingWriter
from . import codecs
from .fs import source_fs
from .naming import parse_cipher_name

LOG = logging.getLogger(__name__)


def _prog(proc):
    args = proc.args
    return args[0] if isinstance(args, (list, tuple)) else str(args)


def _kill(procs):
    for p in procs:
        try:
            p.kill()
        except Exception:
            pass


def _close(stream):
    if stream is not None:
        try:
            stream.close()
        except OSError:
            pass


def _unlink(path):
    if path and os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def _reap(procs):
    """Wait on subprocesses; raise if any exited non-zero.

    ``tar`` exit code 1 ("some files differ / a file changed as we read it") is
    tolerated with a warning: on live data a file may change mid-archive, which
    does not invalidate the archive we produced.
    """
    for p in procs:
        p.wait()
    bad = []
    for p in procs:
        if p.returncode in (0, None):
            continue
        if _prog(p) == 'tar' and p.returncode == 1:
            LOG.warning('tar exited 1 (a file may have changed during read); continuing')
            continue
        bad.append(p)
    if bad:
        raise ValueError('subprocess failed: ' + ', '.join(
            f'{_prog(p)} (rc={p.returncode})' for p in bad))


def pack_item(job):
    """Transform + encrypt one item. ``job`` is a dict; returns a result dict."""
    entry = job['entry']
    relpath = entry['relpath']
    result = {'relpath': relpath, 'status': 'error', 'error': None}
    procs = []
    raw = None
    cipher_path = os.path.join(job['working_dir'], entry['cipher_relpath'])
    try:
        fs = source_fs(job['source_endpoint'])
        codec_name = entry.get('codec', 'none')

        if entry['kind'] == 'file':
            raw, procs = fs.open_file(relpath)
        elif entry['kind'] == 'tar':
            raw, procs = fs.tar_dir(relpath)
            argv = codecs.compressor_argv(codec_name, entry.get('codec_level'))
            if argv:
                comp = subprocess.Popen(argv, stdin=raw, stdout=subprocess.PIPE)
                raw.close()          # let the compressor own the tar pipe (SIGPIPE)
                raw = comp.stdout
                procs.append(comp)
        else:
            raise ValueError(f'pack_item cannot handle kind {entry["kind"]!r}')

        os.makedirs(os.path.dirname(cipher_path) or '.', exist_ok=True)

        reader = HashingReader(raw)
        with open(cipher_path, 'wb') as fout:
            writer = HashingWriter(fout)
            job['cryptor'].encrypt_stream(reader, writer)
            writer.flush()

        _reap(procs)

        result.update(
            status='done',
            src_sha256=reader.hexdigest(),
            src_size=reader.count,
            cipher_size=writer.count,
            cipher_sha256=writer.hexdigest(),
        )
        LOG.debug('Packed %s -> %s (%d -> %d bytes)', relpath, cipher_path,
                  reader.count, writer.count)
    except Exception as e:  # keep one bad item from killing the whole run
        LOG.error('Failed to pack %s: %s', relpath, e)
        _kill(procs)
        _unlink(cipher_path)   # don't leave a truncated ciphertext behind
        result['error'] = str(e)
    finally:
        _close(raw)
    return result


def unpack_item(job):
    """Decrypt + decompress + untar (or write) one item into the output root."""
    item = job['item']
    relpath = item['relpath']
    cipher_path = job['cipher_path']
    out_root = job['out_root']
    result = {'relpath': relpath, 'status': 'error', 'error': None}
    procs = []
    dest_file = None
    kind = None
    try:
        kind = item['kind']
        codec_name = item.get('codec', 'none')
        if kind not in ('file', 'tar'):  # infer if the catalog was absent
            _, kind, codec_name = parse_cipher_name(item['cipher_relpath'])

        with open(cipher_path, 'rb') as cin:
            if kind == 'file':
                dest_file = os.path.join(out_root, relpath)
                os.makedirs(os.path.dirname(dest_file) or '.', exist_ok=True)
                with open(dest_file, 'wb') as fout:
                    writer = HashingWriter(fout)
                    job['cryptor'].decrypt_stream(cin, writer)
                    writer.flush()
                _restore_meta(dest_file, item)
            else:  # tar
                untar = subprocess.Popen(['tar', '-x', '-C', out_root], stdin=subprocess.PIPE)
                procs.append(untar)
                argv = codecs.decompressor_argv(codec_name)
                if argv:
                    decomp = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=untar.stdin)
                    untar.stdin.close()      # only the decompressor feeds tar now
                    procs.insert(0, decomp)
                    sink = decomp.stdin
                else:
                    sink = untar.stdin
                writer = HashingWriter(sink)
                job['cryptor'].decrypt_stream(cin, writer)
                sink.close()
                _reap(procs)

        expected = item.get('src_sha256')
        if expected and writer.hexdigest() != expected:
            raise ValueError(f'Integrity check failed for {relpath}: SHA-256 mismatch')

        result.update(status='done', plain_sha256=writer.hexdigest(), plain_size=writer.count)
        LOG.debug('Unpacked %s (%s, %d bytes, SHA-256 %s)', relpath, kind, writer.count,
                  'verified' if expected else 'not recorded')
    except Exception as e:
        LOG.error('Failed to unpack %s: %s', relpath, e)
        _kill(procs)
        if kind == 'file':
            _unlink(dest_file)   # remove the partial plaintext file
        result['error'] = str(e)
    return result


def _restore_meta(path, item, follow_symlinks=True):
    """Restore permission bits and mtime recorded in the catalog."""
    mode = item.get('src_mode')
    if mode is not None and follow_symlinks:
        try:
            os.chmod(path, stat.S_IMODE(mode))
        except OSError as e:
            LOG.warning('Could not chmod %s: %s', path, e)
    mtime = item.get('src_mtime')
    if mtime is not None:
        try:
            os.utime(path, (mtime, mtime), follow_symlinks=follow_symlinks)
        except (OSError, NotImplementedError) as e:
            LOG.warning('Could not set mtime on %s: %s', path, e)
