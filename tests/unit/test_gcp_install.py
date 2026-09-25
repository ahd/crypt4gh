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
                        lambda cmd, **kw: seen.update(cmd=cmd) or _FakeProc())
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


class _FakeProc:
    """A launched ``-start`` process: alive until ``returncode`` is set."""
    def __init__(self, returncode=None):
        self.returncode = returncode

    def poll(self):
        return self.returncode


def _clock(monkeypatch, step=10.0):
    """A monotonic clock that advances ``step`` seconds per reading."""
    t = {'now': 0.0}

    def tick():
        t['now'] += step
        return t['now']
    monkeypatch.setattr(g.time, 'monotonic', tick)
    monkeypatch.setattr(g.time, 'sleep', lambda _s: None)


def test_start_verify_times_out(monkeypatch, tmp_path):
    # Our own launched instance never becomes reachable, even after the one
    # restart -> clear error.
    launches = []
    connected = iter([False, True, True])
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: next(connected))
    monkeypatch.setattr(g, '_instance_pids', lambda cfg: [])
    monkeypatch.setattr(g, 'stop', lambda l, config_dir=None: launches.append('stop'))
    monkeypatch.setattr(g, '_launch', lambda *a: launches.append('launch') or
                        (_FakeProc(), tmp_path / 'gcp-start.log'))
    _clock(monkeypatch)
    with pytest.raises(g.InstallError, match='not reachable via the Globus transfer API'):
        g.start('gcp', config_dir=tmp_path, timeout=30, verify=lambda: False)
    assert launches == ['launch', 'stop', 'launch']


def test_start_recovers_wedged_preexisting_instance(monkeypatch, tmp_path):
    # Live failure (ih8.10): local -status says connected, the Globus service
    # says GCDisconnected.  An instance we did not start gets one clean restart.
    calls = []
    reachable = {'up': False}             # the service can only see a relaunched one

    def launch(launcher, cfg, restrict_paths):
        calls.append(('launch', restrict_paths))
        reachable['up'] = True
        return _FakeProc(), tmp_path / 'gcp-start.log'

    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: True)
    monkeypatch.setattr(g, 'stop', lambda l, config_dir=None: calls.append('stop'))
    monkeypatch.setattr(g, '_launch', launch)
    _clock(monkeypatch)
    g.start('gcp', config_dir=tmp_path, restrict_paths=['rw~/'],
            verify=lambda: reachable['up'])
    assert calls == ['stop', ('launch', ['rw~/'])]


def test_start_fails_fast_when_launched_process_dies(monkeypatch, tmp_path):
    log = tmp_path / 'gcp-start.log'
    log.write_text('Another Globus Connect Personal is currently running\n')
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: False)
    monkeypatch.setattr(g, '_instance_pids', lambda cfg: [])
    monkeypatch.setattr(g, '_launch', lambda *a: (_FakeProc(returncode=1), log))
    _clock(monkeypatch, step=0.0)         # the deadline never arrives
    with pytest.raises(g.InstallError, match=r'exited \(rc=1\)[\s\S]*currently running'):
        g.start('gcp', config_dir=tmp_path)


def test_start_stops_running_but_disconnected_instance_first(monkeypatch, tmp_path):
    order = []
    connected = iter([False, True])
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: next(connected))
    monkeypatch.setattr(g, '_instance_pids', lambda cfg: [4242])
    monkeypatch.setattr(g, 'stop', lambda l, config_dir=None: order.append('stop'))
    monkeypatch.setattr(g, '_launch',
                        lambda *a: order.append('launch') or (_FakeProc(), tmp_path / 'l'))
    _clock(monkeypatch)
    g.start('gcp', config_dir=tmp_path)
    assert order == ['stop', 'launch']      # never two instances on one config dir


def test_stop_waits_for_process_exit(monkeypatch, tmp_path):
    # -stop returns at once; the instance exits a few polls later.
    monkeypatch.setattr(g, '_capture', lambda *a, **k: (0, ''))
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: False)
    pids = iter([[4242], [4242], []])
    monkeypatch.setattr(g, '_instance_pids', lambda cfg: next(pids))
    monkeypatch.setattr(g.os, 'kill', lambda *a: pytest.fail('must not signal'))
    _clock(monkeypatch, step=1.0)
    g.stop('gcp', config_dir=tmp_path)
    with pytest.raises(StopIteration):     # polled until the pid was gone
        next(pids)


def test_stop_escalates_to_sigterm(monkeypatch, tmp_path):
    killed = []
    monkeypatch.setattr(g, '_capture', lambda *a, **k: (0, ''))
    monkeypatch.setattr(g, 'is_connected', lambda *a, **k: False)
    monkeypatch.setattr(g, '_instance_pids', lambda cfg: [] if killed else [4242])
    monkeypatch.setattr(g.os, 'kill', lambda pid, sig: killed.append((pid, sig)))
    _clock(monkeypatch)
    g.stop('gcp', config_dir=tmp_path, timeout=5)
    assert killed == [(4242, g.signal.SIGTERM)]


def test_instance_pids_finds_start_process_for_config_dir(tmp_path):
    import subprocess
    import sys
    cfg = tmp_path / 'cfg'
    other = tmp_path / 'other'
    sleeper = 'import time; time.sleep(30)'
    mine = subprocess.Popen([sys.executable, '-c', sleeper, '-dir', str(cfg), '-start'])
    theirs = subprocess.Popen([sys.executable, '-c', sleeper, '-dir', str(other), '-start'])
    status = subprocess.Popen([sys.executable, '-c', sleeper, '-dir', str(cfg), '-status'])
    try:
        assert g._instance_pids(cfg) == [mine.pid]
    finally:
        for p in (mine, theirs, status):
            p.kill()
            p.wait()
    assert g._instance_pids(None) == []


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


def test_main_setup_and_start_honour_dir(monkeypatch, tmp_path):
    # --start used to run a foreground `-start` (never returned) and both
    # --setup-key and --start ignored --dir.
    calls = []
    monkeypatch.setattr(g, 'ensure_installed', lambda **k: 'gcp')
    monkeypatch.setattr(g, 'setup', lambda l, key, config_dir=None: calls.append(('setup', key, config_dir)))
    monkeypatch.setattr(g, 'start', lambda l, config_dir=None: calls.append(('start', config_dir)))
    cfg = tmp_path / 'cfg'
    assert g.main(['--setup-key', 'KEY', '--start', '--dir', str(cfg)]) == 0
    assert calls == [('setup', 'KEY', cfg), ('start', cfg)]
