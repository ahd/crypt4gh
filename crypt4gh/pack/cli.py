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
from . import api

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
def _add_common(p):
    p.add_argument('--working', metavar='DIR',
                   help='Local working/staging directory (default: the destination when local, '
                        'else $C4GH_WORKDIR or ./crypt4gh-work). The SQLite catalog lives at its root.')
    p.add_argument('--jobs', '-j', type=int, default=0, metavar='N',
                   help='Number of parallel workers (default: min(cpu_count, 8))')
    p.add_argument('-v', '--verbose', action='count', default=0, help='Increase logging verbosity')
    p.add_argument('source', help='Source directory (local path or [user@]host:/path)')
    p.add_argument('dest', help='Destination directory (local path or [user@]host:/path)')


def _build_parser(verb):
    prog = f'{PROG} {verb}'
    if verb == 'pack':
        p = argparse.ArgumentParser(prog=prog, description='Recursively encrypt a directory tree.')
        p.add_argument('--sk', metavar='PATH', help='Our Curve25519 secret key (sender). '
                       'If omitted, an ephemeral key is generated.')
        p.add_argument('--recipient_pk', metavar='PATH', action='append', default=[], required=True,
                       help="Recipient's Curve25519 public key (repeatable)")
        p.add_argument('--tar', action='store_true',
                       help='Tar each top-level subdirectory into one archive before encryption')
        p.add_argument('--compress', default='none', metavar='CODEC',
                       help='Compress tarred subdirs: none (default), gzip, bzip2 or zstd, '
                            'optionally with a level, e.g. gzip:9 or zstd:19 (requires --tar)')
    elif verb == 'unpack':
        p = argparse.ArgumentParser(prog=prog, description='Recursively decrypt a directory tree.')
        p.add_argument('--sk', metavar='PATH', help='Our Curve25519 secret key (recipient)')
        p.add_argument('--sender_pk', metavar='PATH',
                       help="Peer's public key to verify provenance (optional)")
    else:  # pragma: no cover
        raise ValueError(f'Unknown verb {verb!r}')
    _add_common(p)
    return p


def _configure_logging(verbose):
    level = logging.CRITICAL
    if os.getenv('C4GH_DEBUG'):
        level = logging.DEBUG
    elif verbose >= 2:
        level = logging.DEBUG
    elif verbose == 1:
        level = logging.INFO
    logging.basicConfig(stream=sys.stderr, level=level, format='[%(levelname)s] %(message)s')


# ----------------------------------------------------------------------
# entry point
# ----------------------------------------------------------------------
def main(argv):
    verb, rest = argv[0], argv[1:]
    args = _build_parser(verb).parse_args(rest)
    _configure_logging(args.verbose)

    try:
        if verb == 'pack':
            seckey = _load_seckey(args.sk, generate=True)
            recipients = [_load_pubkey(pk) for pk in args.recipient_pk]
            summary = api.pack(args.source, args.dest, seckey=seckey,
                               recipient_pubkeys=recipients, tar=args.tar,
                               compress=args.compress, working_dir=args.working, jobs=args.jobs)
        else:
            seckey = _load_seckey(args.sk)
            sender_pk = _load_pubkey(args.sender_pk) if args.sender_pk else None
            summary = api.unpack(args.source, args.dest, seckey=seckey,
                                 sender_pubkey=sender_pk, working_dir=args.working, jobs=args.jobs)
    except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError) as e:
        print(f'{verb}: {e}', file=sys.stderr)
        sys.exit(1)

    print(f'{verb}: {summary["done"]} item(s) done, {summary["error"]} error(s)', file=sys.stderr)
    return 0
