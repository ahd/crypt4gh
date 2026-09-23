# -*- coding: utf-8 -*-
"""Unit tests for the Globus Connect Personal installer.

These never touch the network: a synthetic tarball is served via a ``file://``
URL so the download/verify/extract/symlink path is exercised end to end.
"""
import io
import os
import stat
import hashlib
import tarfile

import pytest

from crypt4gh.pack import gcp_install as g


def _make_tgz(path, top='globusconnectpersonal-9.9.9', launcher_mode=0o644):
    """Write a minimal GCP-shaped tarball to ``path`` and return its sha256."""
    with tarfile.open(path, 'w:gz') as tar:
        body = b'#!/bin/sh\necho fake\n'
        info = tarfile.TarInfo(f'{top}/globusconnectpersonal')
        info.size = len(body)
        info.mode = launcher_mode
        tar.addfile(info, io.BytesIO(body))
        extra = b'lib\n'
        sub = tarfile.TarInfo(f'{top}/gt/README')
        sub.size = len(extra)
        tar.addfile(sub, io.BytesIO(extra))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_download_verifies_checksum(tmp_path):
    src = tmp_path / 'src.tgz'
    sha = _make_tgz(src)
    dest = tmp_path / 'out.tgz'
    got = g._download(src.as_uri(), dest, expected_sha256=sha)
    assert got == sha
    assert dest.read_bytes() == src.read_bytes()


def test_download_rejects_bad_checksum(tmp_path):
    src = tmp_path / 'src.tgz'
    _make_tgz(src)
    with pytest.raises(g.InstallError, match='checksum mismatch'):
        g._download(src.as_uri(), tmp_path / 'out.tgz', expected_sha256='deadbeef')


def test_extract_and_link(tmp_path):
    src = tmp_path / 'src.tgz'
    _make_tgz(src, launcher_mode=0o644)  # not executable in the archive
    dist = g._safe_extract(src, tmp_path / 'share')
    assert dist.name == 'globusconnectpersonal-9.9.9'

    link = g._link_launcher(dist, tmp_path / 'bin')
    assert link.is_symlink()
    assert os.readlink(link) == str(dist / 'globusconnectpersonal')
    # launcher was made executable even though the archive entry was 0644
    assert os.stat(dist / 'globusconnectpersonal').st_mode & stat.S_IXUSR


def test_link_is_idempotent(tmp_path):
    src = tmp_path / 'src.tgz'
    _make_tgz(src)
    dist = g._safe_extract(src, tmp_path / 'share')
    bindir = tmp_path / 'bin'
    first = g._link_launcher(dist, bindir)
    second = g._link_launcher(dist, bindir)  # must not raise on existing link
    assert first == second and second.is_symlink()


def test_extract_rejects_multi_top(tmp_path):
    bad = tmp_path / 'bad.tgz'
    with tarfile.open(bad, 'w:gz') as tar:
        for name in ('a/x', 'b/y'):
            info = tarfile.TarInfo(name)
            info.size = 1
            tar.addfile(info, io.BytesIO(b'x'))
    with pytest.raises(g.InstallError, match='unexpected archive layout'):
        g._safe_extract(bad, tmp_path / 'out')


def test_extract_rejects_traversal(tmp_path):
    bad = tmp_path / 'evil.tgz'
    with tarfile.open(bad, 'w:gz') as tar:
        info = tarfile.TarInfo('../evil')
        info.size = 1
        tar.addfile(info, io.BytesIO(b'x'))
    with pytest.raises(g.InstallError):
        g._safe_extract(bad, tmp_path / 'out')


def test_ensure_installed_noop_when_on_path(tmp_path, monkeypatch):
    sentinel = tmp_path / 'globusconnectpersonal'
    sentinel.write_text('#!/bin/sh\n')
    monkeypatch.setattr(g, 'find_on_path', lambda name=g.LAUNCHER_NAME: sentinel)

    def _boom(*a, **k):  # download must never be called on the no-op path
        raise AssertionError('should not download when already on PATH')

    monkeypatch.setattr(g, '_download', _boom)
    assert g.ensure_installed() == sentinel


def test_ensure_installed_rejects_non_linux(monkeypatch):
    monkeypatch.setattr(g.platform, 'system', lambda: 'Darwin')
    with pytest.raises(g.InstallError, match='Linux-only'):
        g.ensure_installed(force=True)


# ----------------------------------------------------------------------
# usability flow: status / setup / start / ensure_usable (all mocked)
# ----------------------------------------------------------------------
@pytest.mark.parametrize('rc, out, expected', [
    (0, 'Globus Online: connected\nTransfer Status: idle', True),
    (0, 'No Globus Connect Personal connected to Globus Online Service', False),
    (1, 'Globus Online: not connected', False),
    (0, 'unexpected gibberish', False),
])
def test_is_connected_parses_status(monkeypatch, rc, out, expected):
    monkeypatch.setattr(g, '_capture', lambda *a, **k: (rc, out))
    assert g.is_connected('gcp') is expected


def test_setup_requires_key():
    with pytest.raises(g.InstallError, match='setup key is required'):
        g.setup('gcp', '')


def test_setup_passes_dir_and_key(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(g, '_capture',
                        lambda launcher, *a, config_dir=None: seen.update(args=a, dir=config_dir) or (0, ''))
    g.setup('gcp', 'KEY123', config_dir=tmp_path)
    assert seen['args'] == ('-setup', '--setup-key', 'KEY123')
    assert seen['dir'] == tmp_path


def test_start_waits_for_connected(monkeypatch, tmp_path):
    # First status: not connected (triggers Popen); then connected.
    states = iter([False, True])
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: next(states))
    popen = []
    monkeypatch.setattr(g.subprocess, 'Popen', lambda cmd, **kw: popen.append(cmd))
    monkeypatch.setattr(g.time, 'sleep', lambda _s: None)
    g.start('gcp', config_dir=tmp_path, timeout=30)
    assert popen and popen[0][-1] == '-start'


def test_start_times_out(monkeypatch, tmp_path):
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: False)
    monkeypatch.setattr(g.subprocess, 'Popen', lambda cmd, **kw: None)
    monkeypatch.setattr(g.time, 'sleep', lambda _s: None)
    # Make the deadline elapse immediately.
    t = iter([0.0, 100.0, 200.0])
    monkeypatch.setattr(g.time, 'monotonic', lambda: next(t))
    with pytest.raises(g.InstallError, match='did not report "connected"'):
        g.start('gcp', config_dir=tmp_path, timeout=1)


def test_create_setup_key_parses_json(monkeypatch):
    monkeypatch.setattr(g.shutil, 'which', lambda _n: '/usr/bin/globus')
    seen = {}

    class _P:
        stdout = '{"id": "EP-UUID", "globus_connect_setup_key": "KEY-XYZ"}'

    def fake_run(argv, **k):
        seen['argv'] = argv
        return _P()

    monkeypatch.setattr(g.subprocess, 'run', fake_run)
    ep_id, key = g.create_setup_key('my-endpoint')
    assert (ep_id, key) == ('EP-UUID', 'KEY-XYZ')
    # Uses the current CLI surface, not the removed `globus endpoint create`.
    assert seen['argv'][:4] == ['globus', 'gcp', 'create', 'mapped']
    assert 'my-endpoint' in seen['argv']


def test_create_setup_key_needs_cli(monkeypatch):
    monkeypatch.setattr(g.shutil, 'which', lambda _n: None)
    with pytest.raises(g.InstallError, match='globus. CLI is needed'):
        g.create_setup_key('x')


def test_ensure_usable_noop_when_connected(monkeypatch):
    monkeypatch.setattr(g, 'ensure_installed', lambda **k: 'gcp')
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: True)
    monkeypatch.setattr(g, 'setup', lambda *a, **k: pytest.fail('should not set up'))
    launcher, ep_id = g.ensure_usable(config_dir=None)
    assert launcher == 'gcp' and ep_id is None


def test_ensure_usable_full_flow(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(g, 'ensure_installed', lambda **k: 'gcp')
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: False)
    monkeypatch.setattr(g, 'create_setup_key', lambda name: ('EP-UUID', 'KEY'))
    monkeypatch.setattr(g, 'setup', lambda l, key, config_dir=None: calls.append(('setup', key)))
    monkeypatch.setattr(g, 'start', lambda l, config_dir=None: calls.append(('start',)))
    launcher, ep_id = g.ensure_usable(config_dir=tmp_path)  # tmp_path has no lta/client-id.txt
    assert ep_id == 'EP-UUID'
    assert calls == [('setup', 'KEY'), ('start',)]
