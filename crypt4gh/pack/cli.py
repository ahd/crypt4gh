# -*- coding: utf-8 -*-
"""Command-line interface for the ``pack`` and ``unpack`` verbs.

Dispatched from :mod:`crypt4gh.__main__` before the docopt CLI, so the existing
streaming verbs are untouched.  Uses argparse (as the completions tool does),
since these verbs carry many options.
"""

import os
import sys
import sqlite3
import logging
import argparse
import functools
import subprocess
from getpass import getpass

from .. import __version__, PROG
from ..keys import get_public_key, get_private_key
from . import api, logsetup
from .gcp_install import InstallError
from .globus import GlobusError

LOG = logging.getLogger(__name__)

DEFAULT_SK = os.getenv('C4GH_SECRET_KEY')


# ----------------------------------------------------------------------
# key helpers (mirrors crypt4gh.cli, adapted to argparse)
# ----------------------------------------------------------------------
def _passphrase_cb(path):
    pw = os.getenv('C4GH_PASSPHRASE')
    if pw is not None:
        print('Warning: Using a passphrase in an environment variable is insecure', file=sys.stderr)
        return lambda: pw
    return functools.partial(getpass, prompt=f'Passphrase for {path}: ')


def _load_seckey(path, generate=False):
    path = path or DEFAULT_SK
    if not path:
        if generate:
            LOG.info('No secret key given; generating an ephemeral sender key')
            return os.urandom(32)
        raise ValueError('A secret key is required (--sk or C4GH_SECRET_KEY)')
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        raise ValueError(f'Secret key not found: {path}')
    return get_private_key(path, _passphrase_cb(path))


def _load_pubkey(path):
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        raise ValueError(f'Public key not found: {path}')
    return get_public_key(path)


# ----------------------------------------------------------------------
# parsers
# ----------------------------------------------------------------------
_DESCRIPTION = {
    'pack': """\
Recursively encrypt a directory tree, leaving the source plaintext untouched.

Each file (or, with --tar, each top-level subdirectory as one archive) is
encrypted into a staging tree in the working directory, alongside a SQLite
catalog (catalog.sqlite) of sizes, modes, mtimes and SHA-256s; the staged
tree is then moved to DEST, so only ciphertext is pushed.  A remote SOURCE is
streamed over ssh and its plaintext is never written to disk here.""",
    'unpack': """\
Recursively decrypt a tree made by `pack`, restoring directories, symlinks,
permissions and mtimes, and verifying each item's SHA-256 against the
catalog.  A remote SOURCE is first pulled into <working>/ciphertext; the
source ciphertext is never modified.""",
}

_EPILOG = """\
endpoints (SOURCE / DEST):
  /local/path                  a local directory
  [user@]host:/path            over ssh (rsync); at most one side remote
  globus:<collection-id>:/path a Globus collection (GridFTP, files at rest)

globus: legs
  The local side of a Globus transfer is this host's Globus Connect Personal
  (GCP) endpoint, which crypt4gh manages before each transfer:
    1. find it: --globus-endpoint, else $C4GH_GLOBUS_LOCAL_ENDPOINT, else the
       state file ~/.config/crypt4gh/globus.json (written by
       `crypt4gh-install-gcp --ensure-usable`), else `globus endpoint local-id`;
    2. share the working directory with it (GCP -restrict-paths; a restart);
    3. start it if it is down, and wait until the Globus service can really
       reach it (restarting once if it claims "connected" but cannot be seen);
    4. transfer (recursive, --sync-level checksum) and check the task SUCCEEDED.
  With no endpoint configured this is an error unless --install-gcp (or
  C4GH_GLOBUS_AUTO_INSTALL=1) lets it install and register one.  Requires an
  authenticated `globus` CLI (`globus login`).  The endpoint's own output goes
  to <config-dir>/gcp-start.log.

environment variables:
  C4GH_SECRET_KEY             default for --sk
  C4GH_PASSPHRASE             passphrase for the secret key instead of a prompt
                              (insecure; prints a warning)
  C4GH_WORKDIR                default working directory
  C4GH_LOG                    default for --log
  C4GH_DEBUG                  debug output on the terminal (may show secrets)
  C4GH_GLOBUS_LOCAL_ENDPOINT  local Globus endpoint id (see above)
  C4GH_GLOBUS_AUTO_INSTALL    1 = allow installing a GCP endpoint (--install-gcp)
  XDG_CONFIG_HOME             relocates the state file ($XDG_CONFIG_HOME/crypt4gh)
"""

_EXAMPLES = {
    'pack': """
examples:
  crypt4gh pack --sk me.sec --recipient_pk them.pub ./data ./vault
  crypt4gh pack --sk me.sec --recipient_pk them.pub --tar --compress zstd:19 \\
      ./data user@host:/incoming
  crypt4gh pack -v --log pack.log --sk me.sec --recipient_pk them.pub \\
      --working /scratch/w0 ./data globus:<collection-id>:/incoming/
""",
    'unpack': """
examples:
  crypt4gh unpack --sk me.sec ./vault ./restored
  crypt4gh unpack -v --log unpack.log --sk me.sec --sender_pk them.pub \\
      --working /scratch/w1 globus:<collection-id>:/incoming/ ./restored
""",
}


def _add_common(p, verb):
    default_working = ('the destination when it is local, else ' if verb == 'pack' else '')
    p.add_argument('--working', metavar='DIR',
                   help=f'Local working/staging directory (default: {default_working}'
                        '$C4GH_WORKDIR, else ./crypt4gh-work). Must hold the whole staged set. '
                        'For a globus: leg it is shared with the local Globus endpoint.')
    p.add_argument('--jobs', '-j', type=int, default=0, metavar='N',
                   help='Number of parallel workers (default: min(cpu_count, 8))')
    p.add_argument('-v', '--verbose', action='count', default=0,
                   help='More detail on the terminal: -v for progress, -vv for debug')
    p.add_argument('--log', metavar='FILE', default=os.getenv('C4GH_LOG'),
                   help='Also log to FILE (default: $C4GH_LOG): a JSON logging.config '
                        'dictConfig document if FILE is one (as for the streaming verbs), '
                        'else a file that records are appended to at INFO (DEBUG with -vv), '
                        'regardless of -v. Covers workers, directory and Globus operations.')

    g = p.add_argument_group('globus endpoint (only used for a globus: source/dest)')
    g.add_argument('--globus-endpoint', metavar='ID',
                   help='Pin the local Globus endpoint id (overrides '
                        'C4GH_GLOBUS_LOCAL_ENDPOINT, the state file and CLI lookup).')
    g.add_argument('--globus-config-dir', metavar='DIR',
                   help='Config dir of the local Globus Connect Personal endpoint '
                        '(passed as -dir; default: from the state file). Needed to '
                        'start/share an isolated endpoint.')
    g.add_argument('--globus-endpoint-name', metavar='NAME',
                   help='Display name to use when auto-installing an endpoint '
                        '(default: crypt4gh-<hostname>).')
    g.add_argument('--install-gcp', action='store_true',
                   help='Auto-install and register a Globus Connect Personal endpoint '
                        'if none is configured (also enabled by C4GH_GLOBUS_AUTO_INSTALL=1). '
                        'Off by default: a missing endpoint is otherwise an error.')

    p.add_argument('source', help='Source directory: local path, [user@]host:/path (ssh), '
                                  'or globus:<collection-id>:/path')
    p.add_argument('dest', help='Destination directory: local path, [user@]host:/path (ssh), '
                                'or globus:<collection-id>:/path')


def _build_parser(verb):
    if verb not in _DESCRIPTION:  # pragma: no cover
        raise ValueError(f'Unknown verb {verb!r}')
    p = argparse.ArgumentParser(prog=f'{PROG} {verb}', description=_DESCRIPTION[verb],
                                epilog=_EPILOG + _EXAMPLES[verb],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    if verb == 'pack':
        p.add_argument('--sk', metavar='PATH',
                       help='Our Curve25519 secret key, as sender (default: $C4GH_SECRET_KEY; '
                            'if neither is given, an ephemeral key is generated)')
        p.add_argument('--recipient_pk', metavar='PATH', action='append', default=[], required=True,
                       help="Recipient's Curve25519 public key (repeatable: any one "
                            "recipient can decrypt)")
        p.add_argument('--tar', action='store_true',
                       help='Tar each top-level subdirectory into one archive before encryption '
                            '(loose files at the top are still encrypted one by one)')
        p.add_argument('--compress', default='none', metavar='CODEC',
                       help='Compress tarred subdirs: none (default), gzip, bzip2 or zstd, '
                            'optionally with a level, e.g. gzip:9 or zstd:19 (requires --tar)')
    else:
        p.add_argument('--sk', metavar='PATH',
                       help='Our Curve25519 secret key, as recipient (default: $C4GH_SECRET_KEY)')
        p.add_argument('--sender_pk', metavar='PATH',
                       help="Sender's public key: reject anything not encrypted by them "
                            "(optional provenance check)")
    _add_common(p, verb)
    return p


# ----------------------------------------------------------------------
# entry point
# ----------------------------------------------------------------------
def main(argv):
    verb, rest = argv[0], argv[1:]
    args = _build_parser(verb).parse_args(rest)
    logsetup.configure(args.verbose, args.log)

    # Endpoint-management options for a globus: leg (ignored for local/ssh).
    # --install-gcp forces auto-install; without it, auto_install stays None so
    # C4GH_GLOBUS_AUTO_INSTALL can still opt in.
    globus_options = {
        'endpoint_id': args.globus_endpoint,
        'config_dir': args.globus_config_dir,
        'name': args.globus_endpoint_name,
        'auto_install': True if args.install_gcp else None,
    }

    try:
        if verb == 'pack':
            seckey = _load_seckey(args.sk, generate=True)
            recipients = [_load_pubkey(pk) for pk in args.recipient_pk]
            summary = api.pack(args.source, args.dest, seckey=seckey,
                               recipient_pubkeys=recipients, tar=args.tar,
                               compress=args.compress, working_dir=args.working, jobs=args.jobs,
                               globus_options=globus_options)
        else:
            seckey = _load_seckey(args.sk)
            sender_pk = _load_pubkey(args.sender_pk) if args.sender_pk else None
            summary = api.unpack(args.source, args.dest, seckey=seckey,
                                 sender_pubkey=sender_pk, working_dir=args.working, jobs=args.jobs,
                                 globus_options=globus_options)
    except KeyboardInterrupt:
        LOG.error('%s: interrupted', verb, extra=logsetup.QUIET)
        print(f'{verb}: interrupted', file=sys.stderr)
        sys.exit(130)
    except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError,
            GlobusError, InstallError) as e:
        LOG.error('%s failed: %s', verb, e, extra=logsetup.QUIET)
        print(f'{verb}: {e}', file=sys.stderr)
        sys.exit(1)

    done = f'{verb}: {summary["done"]} item(s) done, {summary["error"]} error(s)'
    LOG.info('%s', done, extra=logsetup.QUIET)
    print(done, file=sys.stderr)
    return 0
