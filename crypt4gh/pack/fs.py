# -*- coding: utf-8 -*-
"""Source filesystem abstraction: local or ssh-remote.

Provides enumeration (for building the work list) and streaming reads (a plain
file, or a ``tar`` of a subdirectory) for the *source* side of a pack run.  The
local implementation uses the OS directly; the remote implementation shells out
to ``ssh`` (``cat``/``tar``/``find``) so plaintext is only ever exposed inside
the ssh channel, never staged on disk.

Note: remote enumeration parses ``find -printf`` output split on tabs, so remote
source paths containing a literal tab or newline are not supported yet (local
paths are fully robust).  Genomic data trees virtually never contain these.
"""

import os
import io
import stat
import shlex
import logging
import posixpath
import subprocess

LOG = logging.getLogger(__name__)


def _kind_from_mode(mode):
    if stat.S_ISLNK(mode):
        return 'symlink'
    if stat.S_ISDIR(mode):
        return 'dir'
    if stat.S_ISREG(mode):
        return 'file'
    return 'other'


class LocalFS:
    def __init__(self, root):
        self.root = os.path.abspath(root)

    def exists(self):
        return os.path.isdir(self.root)

    def children(self):
        """Entry dicts for the immediate children of the root (with metadata)."""
        out = []
        with os.scandir(self.root) as it:
            for e in it:
                st = os.lstat(e.path)
                kind = _kind_from_mode(st.st_mode)
                if kind == 'other':
                    LOG.warning('Skipping unsupported special file: %s', e.path)
                    continue
                out.append(self._entry(e.path, kind, st))
        return sorted(out, key=lambda x: x['relpath'])

    def walk(self):
        """Yield an entry dict for every directory, file and symlink below root."""
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            # Peel symlinked directories out of the descent set; record them as symlinks.
            real_dirs = []
            for d in dirnames:
                full = os.path.join(dirpath, d)
                if os.path.islink(full):
                    yield self._entry(full, 'symlink')
                else:
                    real_dirs.append(d)
                    if os.path.relpath(full, self.root) != '.':
                        yield self._entry(full, 'dir')
            dirnames[:] = real_dirs
            for f in filenames:
                full = os.path.join(dirpath, f)
                st = os.lstat(full)
                kind = _kind_from_mode(st.st_mode)
                if kind == 'other':
                    LOG.warning('Skipping unsupported special file: %s', full)
                    continue
                yield self._entry(full, kind, st)

    def _entry(self, full, kind, st=None):
        st = st or os.lstat(full)
        relpath = os.path.relpath(full, self.root)
        entry = {
            'relpath': relpath,
            'kind': kind,
            'src_mode': stat.S_IMODE(st.st_mode),
            'src_mtime': st.st_mtime,
            'src_size': st.st_size if kind == 'file' else None,
            'symlink_target': os.readlink(full) if kind == 'symlink' else None,
        }
        return entry

    def open_file(self, relpath):
        """Return (stream, procs) for reading a plain file."""
        return open(os.path.join(self.root, relpath), 'rb'), []

    def tar_dir(self, relpath):
        """Return (stream, procs) streaming a ``tar`` of one subdirectory."""
        proc = subprocess.Popen(
            ['tar', '-C', self.root, '-c', '--', relpath],
            stdout=subprocess.PIPE,
        )
        return proc.stdout, [proc]


class RemoteFS:
    """ssh-backed source. ``endpoint`` is a parsed :class:`~crypt4gh.pack.transport.Endpoint`."""

    def __init__(self, endpoint):
        self.ep = endpoint
        self.hostspec = f'{endpoint.user}@{endpoint.host}' if endpoint.user else endpoint.host
        self.root = endpoint.path

    def _ssh(self, remote_cmd, **kw):
        return subprocess.Popen(['ssh', self.hostspec, remote_cmd], **kw)

    def exists(self):
        cmd = f'test -d {shlex.quote(self.root)}'
        return subprocess.call(['ssh', self.hostspec, cmd]) == 0

    def children(self):
        entries = [e for e in self._find(maxdepth=1) if e['relpath'] != '.']
        return sorted(entries, key=lambda x: x['relpath'])

    def walk(self):
        for e in self._find(maxdepth=None):
            if e['relpath'] != '.':
                yield e

    def _find(self, maxdepth=None):
        depth = f'-maxdepth {maxdepth} ' if maxdepth else ''
        # type<TAB>octal-mode<TAB>mtime<TAB>size<TAB>relative-path<TAB>symlink-target
        printf = r'%y\t%m\t%T@\t%s\t%P\t%l\n'
        remote = (f'cd {shlex.quote(self.root)} && '
                  f'find . -mindepth 0 {depth}-printf {shlex.quote(printf)}')
        proc = self._ssh(remote, stdout=subprocess.PIPE, text=True)
        out, _ = proc.communicate()
        if proc.returncode != 0:
            raise ValueError(f'Remote enumeration failed for {self.hostspec}:{self.root}')
        result = []
        for line in out.splitlines():
            if not line:
                continue
            y, mode, mtime, size, relpath, target = line.split('\t', 5)
            relpath = relpath or '.'
            kind = {'f': 'file', 'd': 'dir', 'l': 'symlink'}.get(y, 'other')
            if kind == 'other':
                LOG.warning('Skipping unsupported remote special file: %s', relpath)
                continue
            result.append({
                'relpath': relpath,
                'kind': kind,
                'src_mode': int(mode, 8),
                'src_mtime': float(mtime),
                'src_size': int(size) if kind == 'file' else None,
                'symlink_target': target if kind == 'symlink' else None,
            })
        return result

    def open_file(self, relpath):
        path = posixpath.join(self.root, relpath)
        proc = self._ssh(f'cat -- {shlex.quote(path)}', stdout=subprocess.PIPE)
        return proc.stdout, [proc]

    def tar_dir(self, relpath):
        remote = f'tar -C {shlex.quote(self.root)} -c -- {shlex.quote(relpath)}'
        proc = self._ssh(remote, stdout=subprocess.PIPE)
        return proc.stdout, [proc]


def source_fs(endpoint):
    """Build the right source FS for a parsed endpoint."""
    if endpoint.kind == 'local':
        return LocalFS(endpoint.path)
    if endpoint.kind == 'ssh':
        return RemoteFS(endpoint)
    raise ValueError(f'Unsupported source endpoint kind: {endpoint.kind}')
