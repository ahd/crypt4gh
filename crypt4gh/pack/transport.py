# -*- coding: utf-8 -*-
"""Endpoint parsing and at-rest transfer (local move / rsync-over-ssh).

An endpoint is either a local path or an rsync-style ``[user@]host:/path``.
The staged working directory is materialised locally first; this module then
moves it to (or pulls it from) the endpoint.  A future ``globus`` kind slots in
here: the "stage the lot, then push" model is exactly what Globus needs, since
it transfers files at rest between endpoints.
"""

import os
import re
import shutil
import logging
import subprocess
from dataclasses import dataclass

LOG = logging.getLogger(__name__)

# [user@]host:path  -- host has no slash and there is a colon before any slash.
_REMOTE_RE = re.compile(r'^(?:(?P<user>[^@/]+)@)?(?P<host>[^@/:]+):(?P<path>.*)$')


@dataclass
class Endpoint:
    kind: str          # 'local' | 'ssh' | 'globus'
    path: str
    host: str = None
    user: str = None

    @property
    def is_remote(self):
        return self.kind != 'local'

    def __str__(self):
        if self.kind == 'ssh':
            host = f'{self.user}@{self.host}' if self.user else self.host
            return f'{host}:{self.path}'
        return self.path


def parse_endpoint(spec):
    """Parse a source/dest spec into an :class:`Endpoint`.

    ``host:path`` is remote (ssh); anything else is a local path.  A bare
    Windows-style drive letter is not a concern on the Linux target.
    """
    m = _REMOTE_RE.match(spec)
    if m:
        return Endpoint(kind='ssh', host=m.group('host'), user=m.group('user'),
                        path=m.group('path') or '.')
    return Endpoint(kind='local', path=os.path.abspath(os.path.expanduser(spec)))


def _hostspec(ep):
    return f'{ep.user}@{ep.host}' if ep.user else ep.host


def _rsync(src, dst):
    argv = ['rsync', '-a', '--partial', '--mkpath', src, dst]
    LOG.info('rsync %s -> %s', src, dst)
    subprocess.check_call(argv)


def push(working_dir, dest):
    """Move/copy the staged ciphertext (or plaintext) tree to the destination."""
    src = os.path.join(working_dir, '')  # trailing slash: copy contents
    if dest.kind == 'local':
        os.makedirs(dest.path, exist_ok=True)
        _rsync(src, os.path.join(dest.path, ''))
    elif dest.kind == 'ssh':
        _rsync(src, f'{_hostspec(dest)}:{dest.path}/')
    else:
        raise ValueError(f'Unsupported destination kind: {dest.kind}')


def pull(source, working_dir):
    """Fetch an at-rest tree (e.g. ciphertext for unpack) into the working dir."""
    os.makedirs(working_dir, exist_ok=True)
    dst = os.path.join(working_dir, '')
    if source.kind == 'local':
        _rsync(os.path.join(source.path, ''), dst)
    elif source.kind == 'ssh':
        _rsync(f'{_hostspec(source)}:{source.path}/', dst)
    else:
        raise ValueError(f'Unsupported source kind: {source.kind}')
