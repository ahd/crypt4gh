# -*- coding: utf-8 -*-
"""Endpoint parsing and at-rest transfer (local move / rsync-over-ssh).

An endpoint is a local path, an rsync-style ``[user@]host:/path`` (ssh), or a
``globus:<endpoint-id>:/path`` Globus collection.  The staged working directory
is materialised locally first; this module then moves it to (or pulls it from)
the endpoint.  The "stage the lot, then push" model is exactly what Globus needs,
since GridFTP transfers files at rest between endpoints -- the local side is this
host's Globus Connect Personal endpoint (see :mod:`crypt4gh.pack.globus`).
"""

import os
import re
import shutil
import shlex
import logging
import subprocess
from dataclasses import dataclass

LOG = logging.getLogger(__name__)

# [user@]host:path  -- host has no slash and there is a colon before any slash.
_REMOTE_RE = re.compile(r'^(?:(?P<user>[^@/]+)@)?(?P<host>[^@/:]+):(?P<path>.*)$')

# globus:<endpoint-id>:/collection/path
_GLOBUS_PREFIX = 'globus:'


@dataclass
class Endpoint:
    kind: str          # 'local' | 'ssh' | 'globus'
    path: str
    host: str = None   # ssh hostname, or globus endpoint/collection id
    user: str = None

    @property
    def is_remote(self):
        return self.kind != 'local'

    def __str__(self):
        if self.kind == 'ssh':
            host = f'{self.user}@{self.host}' if self.user else self.host
            return f'{host}:{self.path}'
        if self.kind == 'globus':
            return f'globus:{self.host}:{self.path}'
        return self.path


def parse_endpoint(spec):
    """Parse a source/dest spec into an :class:`Endpoint`.

    * ``globus:<endpoint-id>:/path`` is a Globus collection (checked first, so
      the ssh regex does not mistake the ``globus`` prefix for a hostname).
    * ``[user@]host:path`` is remote (ssh).
    * anything else is a local path.  A bare Windows-style drive letter is not
      a concern on the Linux target.
    """
    if spec.startswith(_GLOBUS_PREFIX):
        ep_id, sep, path = spec[len(_GLOBUS_PREFIX):].partition(':')
        if not sep or not ep_id:
            raise ValueError(
                "Globus endpoint must be 'globus:<endpoint-id>:/path' "
                f'(got {spec!r})')
        return Endpoint(kind='globus', host=ep_id, path=path or '/')
    m = _REMOTE_RE.match(spec)
    if m:
        return Endpoint(kind='ssh', host=m.group('host'), user=m.group('user'),
                        path=m.group('path') or '.')
    return Endpoint(kind='local', path=os.path.abspath(os.path.expanduser(spec)))


def _hostspec(ep):
    return f'{ep.user}@{ep.host}' if ep.user else ep.host


def _rsync(src, dst):
    # NB: no --mkpath (needs rsync 3.2.3+; macOS ships 2.6.9). The destination
    # directory is created explicitly before rsync runs.
    argv = ['rsync', '-a', '--partial', src, dst]
    LOG.info('rsync %s -> %s', src, dst)
    subprocess.check_call(argv)


def _ssh_mkdir(dest):
    subprocess.check_call(['ssh', _hostspec(dest), f'mkdir -p {shlex.quote(dest.path)}'])


def _globus_endpoint_spec(working_dir):
    """Address the local staging dir as ``<local-endpoint-id>:<abspath>``.

    Warns (does not abort) if the dir is not on storage the local Globus
    endpoint exposes: the transfer would then fail or crawl, but a mapped
    collection may legitimately see paths we cannot introspect.
    """
    from . import globus
    local_id = globus.local_endpoint_id()
    ok, reason = globus.working_is_shared(working_dir)
    if not ok:
        LOG.warning('%s', reason)
    return f'{local_id}:{os.path.abspath(working_dir)}'


def push(working_dir, dest):
    """Move/copy the staged ciphertext (or plaintext) tree to the destination."""
    src = os.path.join(working_dir, '')  # trailing slash: copy contents
    if dest.kind == 'local':
        os.makedirs(dest.path, exist_ok=True)
        _rsync(src, os.path.join(dest.path, ''))
    elif dest.kind == 'ssh':
        _ssh_mkdir(dest)
        _rsync(src, f'{_hostspec(dest)}:{dest.path}/')
    elif dest.kind == 'globus':
        from . import globus
        local = _globus_endpoint_spec(working_dir)
        globus.transfer(local, f'{dest.host}:{dest.path}', label='crypt4gh pack')
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
    elif source.kind == 'globus':
        from . import globus
        local = _globus_endpoint_spec(working_dir)
        globus.transfer(f'{source.host}:{source.path}', local, label='crypt4gh unpack')
    else:
        raise ValueError(f'Unsupported source kind: {source.kind}')
