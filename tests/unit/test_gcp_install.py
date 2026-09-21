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
