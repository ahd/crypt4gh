# -*- coding: utf-8 -*-
import os

import pytest

from crypt4gh.pack import transport


def test_parse_local(tmp_path):
    ep = transport.parse_endpoint(str(tmp_path))
    assert ep.kind == 'local'
    assert ep.is_remote is False
    assert os.path.isabs(ep.path)


def test_parse_local_relative():
    ep = transport.parse_endpoint('some/dir')
    assert ep.kind == 'local'
    assert ep.path.endswith('some/dir')


@pytest.mark.parametrize('spec, user, host, path', [
    ('host:/data', None, 'host', '/data'),
    ('u@host:/data', 'u', 'host', '/data'),
    ('host:rel/path', None, 'host', 'rel/path'),
    ('host:', None, 'host', '.'),
])
def test_parse_remote(spec, user, host, path):
    ep = transport.parse_endpoint(spec)
    assert ep.kind == 'ssh'
    assert (ep.user, ep.host, ep.path) == (user, host, path)
    assert ep.is_remote


def test_push_to_ssh_builds_rsync(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(transport.subprocess, 'check_call', lambda argv: calls.append(argv))
    dest = transport.parse_endpoint('bob@example.org:/incoming')
    transport.push(str(tmp_path), dest)
    # It creates the remote dir (ssh mkdir), then rsyncs.
    assert len(calls) == 2
    mkdir_call, rsync_call = calls
    assert mkdir_call[0] == 'ssh' and mkdir_call[1] == 'bob@example.org'
    assert 'mkdir -p' in mkdir_call[2]
    assert rsync_call[0] == 'rsync'
    assert '--mkpath' not in rsync_call          # not portable; must stay gone
    assert rsync_call[-1] == 'bob@example.org:/incoming/'
    assert rsync_call[-2] == os.path.join(str(tmp_path), '')


def test_pull_from_ssh_builds_rsync(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(transport.subprocess, 'check_call', lambda argv: calls.append(argv))
    src = transport.parse_endpoint('host:/data')
    transport.pull(src, str(tmp_path / 'work'))
    argv = calls[0]
    assert argv[0] == 'rsync'
    assert argv[-2] == 'host:/data/'
