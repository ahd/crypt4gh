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


def test_ensure_usable_noop_when_connected(monkeypatch, tmp_path):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(g, 'ensure_installed', lambda **k: 'gcp')
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: True)
    monkeypatch.setattr(g, 'setup', lambda *a, **k: pytest.fail('should not set up'))
    launcher, ep_id = g.ensure_usable(config_dir=None)
    assert launcher == 'gcp' and ep_id is None
    assert g.load_endpoint_state() is None


def _registered_config(tmp_path, ep_id='EP-EXISTING'):
    cfg = tmp_path / 'cfg'
    (cfg / 'lta').mkdir(parents=True)
    (cfg / 'lta' / 'client-id.txt').write_text(ep_id + '\n')
    return cfg


def test_endpoint_id_from_config(tmp_path):
    assert g.endpoint_id_from_config(None) is None
    assert g.endpoint_id_from_config(tmp_path / 'missing') is None
    assert g.endpoint_id_from_config(_registered_config(tmp_path)) == 'EP-EXISTING'


def test_ensure_usable_records_already_connected_endpoint(monkeypatch, tmp_path):
    # An endpoint registered + running before the state file existed must still
    # be adopted into it (found live on hpcapp01, crypt4gh-ih8.9).
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(g, 'ensure_installed', lambda **k: 'gcp')
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: True)
    monkeypatch.setattr(g, 'setup', lambda *a, **k: pytest.fail('should not set up'))
    monkeypatch.setattr(g, 'start', lambda *a, **k: pytest.fail('should not start'))
    cfg = _registered_config(tmp_path)
    launcher, ep_id = g.ensure_usable(config_dir=cfg)
    assert ep_id == 'EP-EXISTING'
    assert g.load_endpoint_state() == {'endpoint_id': 'EP-EXISTING', 'config_dir': str(cfg)}


def test_ensure_usable_records_registered_but_stopped_endpoint(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(g, 'ensure_installed', lambda **k: 'gcp')
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: False)
    monkeypatch.setattr(g, 'create_setup_key', lambda name: pytest.fail('should not create'))
    monkeypatch.setattr(g, 'setup', lambda *a, **k: pytest.fail('should not set up'))
    monkeypatch.setattr(g, 'start', lambda l, config_dir=None: calls.append('start'))
    cfg = _registered_config(tmp_path)
    launcher, ep_id = g.ensure_usable(config_dir=cfg)
    assert ep_id == 'EP-EXISTING' and calls == ['start']
    assert g.load_endpoint_state() == {'endpoint_id': 'EP-EXISTING', 'config_dir': str(cfg)}


def test_ensure_usable_keeps_recorded_restrict_paths(monkeypatch, tmp_path):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(g, 'ensure_installed', lambda **k: 'gcp')
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: True)
    cfg = _registered_config(tmp_path)
    rules = ['rw~/', 'rw/mnt/lustre/staging']
    g.save_endpoint_state('EP-EXISTING', cfg, restrict_paths=rules)
    g.ensure_usable(config_dir=cfg)
    assert g.load_endpoint_state()['restrict_paths'] == rules


def test_ensure_usable_replaces_state_for_other_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(g, 'ensure_installed', lambda **k: 'gcp')
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: True)
    g.save_endpoint_state('EP-OLD', '/elsewhere', restrict_paths=['rw~/', 'rw/old'])
    cfg = _registered_config(tmp_path)
    g.ensure_usable(config_dir=cfg)
    # A different endpoint's shared paths say nothing about this one.
    assert g.load_endpoint_state() == {'endpoint_id': 'EP-EXISTING', 'config_dir': str(cfg)}


def test_ensure_usable_full_flow(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'xdg'))  # isolate the state file
    monkeypatch.setattr(g, 'ensure_installed', lambda **k: 'gcp')
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: False)
    monkeypatch.setattr(g, 'create_setup_key', lambda name: ('EP-UUID', 'KEY'))
    monkeypatch.setattr(g, 'setup', lambda l, key, config_dir=None: calls.append(('setup', key)))
    monkeypatch.setattr(g, 'start', lambda l, config_dir=None: calls.append(('start',)))
    cfg = tmp_path / 'cfg'  # config_dir with no lta/client-id.txt -> fresh registration
    launcher, ep_id = g.ensure_usable(config_dir=cfg)
    assert ep_id == 'EP-UUID'
    assert calls == [('setup', 'KEY'), ('start',)]
    # ...and the created endpoint (with its config dir) was persisted for the transport.
    assert g.load_endpoint_state() == {'endpoint_id': 'EP-UUID', 'config_dir': str(cfg)}


# ----------------------------------------------------------------------
# endpoint state file (save/load)
# ----------------------------------------------------------------------
def test_state_roundtrip(tmp_path):
    p = tmp_path / 'globus.json'
    g.save_endpoint_state('EP-1', '/some/cfg', path=p)
    assert g.load_endpoint_state(path=p) == {'endpoint_id': 'EP-1', 'config_dir': '/some/cfg'}


def test_state_omits_config_dir_when_none(tmp_path):
    p = tmp_path / 'globus.json'
    g.save_endpoint_state('EP-1', None, path=p)
    assert g.load_endpoint_state(path=p) == {'endpoint_id': 'EP-1'}


def test_state_path_honours_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'xdg'))
    assert g._state_path() == tmp_path / 'xdg' / 'crypt4gh' / 'globus.json'


def test_load_endpoint_state_missing_is_none(tmp_path):
    assert g.load_endpoint_state(path=tmp_path / 'nope.json') is None


def test_load_endpoint_state_corrupt_is_none(tmp_path):
    p = tmp_path / 'globus.json'
    p.write_text('{not json')
    assert g.load_endpoint_state(path=p) is None


def test_load_endpoint_state_without_id_is_none(tmp_path):
    p = tmp_path / 'globus.json'
    p.write_text('{"config_dir": "/x"}')
    assert g.load_endpoint_state(path=p) is None


def test_save_endpoint_state_swallows_io_error(monkeypatch):
    # An unwritable location must warn, not raise (state is a convenience).
    def boom(*a, **k):
        raise OSError('nope')
    monkeypatch.setattr(g.Path, 'mkdir', boom)
    g.save_endpoint_state('EP-1', '/c', path='/root/denied/globus.json')  # no exception


# ----------------------------------------------------------------------
# restrict-paths parsing / coverage
# ----------------------------------------------------------------------
def test_restrict_rule_path_parses_access(tmp_path):
    access, path = g.restrict_rule_path('rw' + str(tmp_path))
    assert access == 'rw' and path == os.path.realpath(str(tmp_path))
    assert g.restrict_rule_path('r/pub') == ('r', '/pub')
    assert g.restrict_rule_path('/pub')[0] == 'rw'  # no prefix => rw


def test_restrict_path_covered_prefix(tmp_path):
    rules = ['rw' + str(tmp_path)]
    assert g.restrict_path_covered(str(tmp_path / 'a' / 'b'), rules)
    assert not g.restrict_path_covered('/somewhere/else', rules)


def test_restrict_path_covered_longest_match_n_denies(tmp_path):
    deep = tmp_path / 'deep'
    rules = ['rw' + str(tmp_path), 'n' + str(deep)]
    assert g.restrict_path_covered(str(tmp_path / 'x'), rules)      # broad grant
    assert not g.restrict_path_covered(str(deep / 'x'), rules)      # specific N wins


def test_current_restrict_paths_defaults_to_home(tmp_path):
    assert g.current_restrict_paths(state_path=tmp_path / 'nope.json') == [g.HOME_RULE]


def test_current_restrict_paths_from_state(tmp_path):
    state = tmp_path / 'globus.json'
    g.save_endpoint_state('EP', '/c', restrict_paths=['rw/x'], path=state)
    assert g.current_restrict_paths(state_path=state) == ['rw/x']


# ----------------------------------------------------------------------
# start(restrict_paths) / restart / ensure_path_shared
# ----------------------------------------------------------------------
def test_start_passes_restrict_paths(monkeypatch, tmp_path):
    seen = {}
    states = iter([False, True])  # top guard: not connected; then: connected
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: next(states))
    monkeypatch.setattr(g.subprocess, 'Popen',
                        lambda cmd, **kw: seen.update(cmd=cmd) or object())
    g.start('gcp', config_dir=tmp_path, restrict_paths=['rw~/', 'rw/mnt/x'])
    cmd = seen['cmd']
    assert cmd[cmd.index('-restrict-paths') + 1] == 'rw~/,rw/mnt/x'


def test_restart_stops_then_starts(monkeypatch):
    order = []
    monkeypatch.setattr(g, 'stop', lambda l, config_dir=None: order.append('stop'))
    monkeypatch.setattr(g, 'start',
                        lambda l, config_dir=None, restrict_paths=None, timeout=None, verify=None:
                        order.append(('start', restrict_paths)))
    g.restart('gcp', config_dir='/c', restrict_paths=['rw~/'])
    assert order == ['stop', ('start', ['rw~/'])]


def test_ensure_path_shared_shares_and_restarts(monkeypatch, tmp_path):
    state = tmp_path / 'globus.json'
    calls = []
    monkeypatch.setattr(g, 'restart',
                        lambda launcher, config_dir=None, restrict_paths=None, **k:
                        calls.append((config_dir, restrict_paths)))
    target = tmp_path / 'stage'
    changed = g.ensure_path_shared('gcp', 'EP', '/cfg', str(target), state_path=state)
    assert changed is True
    assert len(calls) == 1                       # exactly one restart
    cfg, rules = calls[0]
    assert cfg == '/cfg'
    assert g.HOME_RULE in rules                  # home preserved
    assert 'rw' + os.path.realpath(str(target)) in rules  # target added (canonical)
    # the augmented rule set was persisted for next time
    assert g.load_endpoint_state(path=state)['restrict_paths'] == rules


def test_ensure_path_shared_noop_when_covered(monkeypatch, tmp_path):
    state = tmp_path / 'globus.json'
    target = tmp_path / 'stage'
    g.save_endpoint_state('EP', '/cfg',
                          restrict_paths=['rw' + os.path.realpath(str(target))],
                          path=state)
    monkeypatch.setattr(g, 'restart',
                        lambda *a, **k: pytest.fail('must not restart when already shared'))
    changed = g.ensure_path_shared('gcp', 'EP', '/cfg', str(target / 'sub'), state_path=state)
    assert changed is False


# ----------------------------------------------------------------------
# start(verify=...) reachability wait (ih8.7)
# ----------------------------------------------------------------------
def test_start_verify_waits_then_succeeds(monkeypatch, tmp_path):
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: True)   # already connected
    monkeypatch.setattr(g.time, 'sleep', lambda _s: None)
    monkeypatch.setattr(g.time, 'monotonic', lambda: 0.0)          # never times out
    reach = iter([False, False, True])                            # 502 lag, then up
    g.start('gcp', config_dir=tmp_path, verify=lambda: next(reach))  # returns cleanly


def test_start_verify_times_out(monkeypatch, tmp_path):
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: True)
    monkeypatch.setattr(g.time, 'sleep', lambda _s: None)
    monkeypatch.setattr(g.time, 'monotonic', iter([0.0, 100.0, 200.0]).__next__)
    with pytest.raises(g.InstallError, match='not reachable via the Globus transfer API'):
        g.start('gcp', config_dir=tmp_path, timeout=1, verify=lambda: False)


def test_restart_passes_verify(monkeypatch):
    seen = {}
    monkeypatch.setattr(g, 'stop', lambda l, config_dir=None: None)
    monkeypatch.setattr(g, 'start',
                        lambda l, config_dir=None, restrict_paths=None, timeout=None, verify=None:
                        seen.update(verify=verify))
    sentinel = lambda: True
    g.restart('gcp', verify=sentinel)
    assert seen['verify'] is sentinel


def test_ensure_path_shared_passes_verify(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(g, 'restart',
                        lambda l, config_dir=None, restrict_paths=None, verify=None:
                        seen.update(verify=verify))
    sentinel = lambda: True
    g.ensure_path_shared('gcp', 'EP', '/c', str(tmp_path / 'stage'),
                         state_path=tmp_path / 'globus.json', verify=sentinel)
    assert seen['verify'] is sentinel
