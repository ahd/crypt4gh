# -*- coding: utf-8 -*-
import os
import subprocess

import pytest

from crypt4gh.pack import transport, globus, gcp_install


# ----------------------------------------------------------------------
# endpoint parsing
# ----------------------------------------------------------------------
@pytest.mark.parametrize('spec, ep_id, path', [
    ('globus:abc-123:/data', 'abc-123', '/data'),
    ('globus:abc-123:rel/path', 'abc-123', 'rel/path'),
    ('globus:abc-123:', 'abc-123', '/'),
])
def test_parse_globus(spec, ep_id, path):
    ep = transport.parse_endpoint(spec)
    assert ep.kind == 'globus'
    assert ep.is_remote
    assert (ep.host, ep.path) == (ep_id, path)


def test_parse_globus_roundtrips_str():
    ep = transport.parse_endpoint('globus:abc-123:/data')
    assert str(ep) == 'globus:abc-123:/data'


@pytest.mark.parametrize('spec', ['globus:abc-123', 'globus::/data', 'globus:'])
def test_parse_globus_rejects_malformed(spec):
    with pytest.raises(ValueError):
        transport.parse_endpoint(spec)


def test_globus_prefix_not_treated_as_ssh_host():
    # The ssh regex would otherwise grab 'globus' as a hostname.
    ep = transport.parse_endpoint('globus:abc-123:/data')
    assert ep.kind == 'globus' and ep.host == 'abc-123'


# ----------------------------------------------------------------------
# CLI wrappers (mocked subprocess -- no live Globus)
# ----------------------------------------------------------------------
class _Fake:
    def __init__(self, stdout=''):
        self.stdout = stdout


@pytest.fixture
def cli(monkeypatch):
    """Record globus CLI invocations; make the binary appear installed."""
    calls = []
    monkeypatch.setattr(globus.shutil, 'which', lambda _n: '/usr/bin/globus')

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv[1:3] == ['endpoint', 'local-id']:
            return _Fake(stdout='LOCAL-EP\n')
        if argv[1] == 'transfer':
            return _Fake(stdout='{"task_id": "TASK-1"}')
        if argv[1:3] == ['task', 'show']:
            return _Fake(stdout='{"status": "SUCCEEDED"}')
        return _Fake(stdout='')

    monkeypatch.setattr(globus.subprocess, 'run', fake_run)
    monkeypatch.delenv(globus.LOCAL_ENDPOINT_ENV, raising=False)
    # No state file unless a test provides one, so the resolver reaches the CLI.
    monkeypatch.setattr(gcp_install, 'load_endpoint_state', lambda **kw: None)
    return calls


def test_ensure_cli_missing(monkeypatch):
    monkeypatch.setattr(globus.shutil, 'which', lambda _n: None)
    with pytest.raises(globus.GlobusError):
        globus.ensure_cli()


def test_local_endpoint_id_from_cli(cli):
    assert globus.local_endpoint_id() == 'LOCAL-EP'
    assert cli[0][1:] == ['endpoint', 'local-id']


def test_local_endpoint_id_env_override(cli, monkeypatch):
    monkeypatch.setenv(globus.LOCAL_ENDPOINT_ENV, 'OVERRIDE-EP')
    assert globus.local_endpoint_id() == 'OVERRIDE-EP'
    assert cli == []  # override short-circuits the CLI


def test_resolve_local_endpoint_from_cli(cli):
    assert globus.resolve_local_endpoint() == ('LOCAL-EP', None)
    assert cli[0][1:] == ['endpoint', 'local-id']


def test_resolve_local_endpoint_env_override(cli, monkeypatch):
    monkeypatch.setenv(globus.LOCAL_ENDPOINT_ENV, 'OVERRIDE-EP')
    assert globus.resolve_local_endpoint() == ('OVERRIDE-EP', None)
    assert cli == []  # env short-circuits both the state file and the CLI


def test_resolve_local_endpoint_from_state(cli, monkeypatch):
    # State file wins over the CLI and carries the isolated endpoint's config dir.
    monkeypatch.setattr(gcp_install, 'load_endpoint_state',
                        lambda **kw: {'endpoint_id': 'STATE-EP',
                                      'config_dir': '/cfg/dir'})
    assert globus.resolve_local_endpoint() == ('STATE-EP', '/cfg/dir')
    assert cli == []  # never falls through to `endpoint local-id`


def test_resolve_local_endpoint_state_without_config_dir(cli, monkeypatch):
    monkeypatch.setattr(gcp_install, 'load_endpoint_state',
                        lambda **kw: {'endpoint_id': 'STATE-EP'})
    assert globus.resolve_local_endpoint() == ('STATE-EP', None)


def test_local_endpoint_id_delegates(cli, monkeypatch):
    monkeypatch.setattr(gcp_install, 'load_endpoint_state',
                        lambda **kw: {'endpoint_id': 'STATE-EP', 'config_dir': '/c'})
    assert globus.local_endpoint_id() == 'STATE-EP'  # id only, drops config dir


def test_submit_transfer_builds_argv(cli):
    task = globus.submit_transfer('SRC:/a', 'DST:/b', label='lbl')
    assert task == 'TASK-1'
    argv = cli[0]
    assert argv[:2] == ['globus', 'transfer']
    assert 'SRC:/a' in argv and 'DST:/b' in argv
    assert '--recursive' in argv
    assert argv[argv.index('--sync-level') + 1] == 'checksum'
    assert argv[argv.index('--label') + 1] == 'lbl'
    assert argv[argv.index('-F') + 1] == 'json'


def test_endpoint_reachable_true(cli):
    assert globus.endpoint_reachable('EP') is True
    assert cli[-1][1:] == ['ls', 'EP:/']  # probes the endpoint root via the API


def test_endpoint_reachable_false_on_error(monkeypatch):
    monkeypatch.setattr(globus.shutil, 'which', lambda _n: '/usr/bin/globus')

    def boom(argv, **kw):
        raise subprocess.CalledProcessError(1, argv, stderr='502 GCDisconnected')

    monkeypatch.setattr(globus.subprocess, 'run', boom)
    assert globus.endpoint_reachable('EP') is False


def test_wait_builds_argv(cli):
    globus.wait('TASK-9', polling_interval=5, timeout=60)
    argv = cli[0]
    assert argv[1:3] == ['task', 'wait'] and argv[3] == 'TASK-9'
    assert argv[argv.index('--polling-interval') + 1] == '5'
    assert argv[argv.index('--timeout') + 1] == '60'


def test_transfer_submits_then_waits(cli):
    globus.transfer('SRC:/a', 'DST:/b')
    calls = [c[1:4] for c in cli]
    # submit, wait, then confirm the terminal status
    assert calls == [['transfer', 'SRC:/a', 'DST:/b'],
                     ['task', 'wait', 'TASK-1'], ['task', 'show', 'TASK-1']]


def test_wait_raises_on_failed_task(monkeypatch):
    # `globus task wait` exits 0 for any terminal state, FAILED included.
    monkeypatch.setattr(globus.shutil, 'which', lambda _n: '/usr/bin/globus')

    def fake_run(argv, **kw):
        if argv[1:3] == ['task', 'show']:
            return _Fake(stdout='{"status": "FAILED", "nice_status": "PERMISSION_DENIED"}')
        return _Fake(stdout='')

    monkeypatch.setattr(globus.subprocess, 'run', fake_run)
    with pytest.raises(globus.GlobusError, match='TASK-2 ended FAILED: PERMISSION_DENIED'):
        globus.wait('TASK-2')


def test_run_captures_stderr(monkeypatch):
    # CLI error text must not spray onto the terminal (seen live while polling
    # a starting endpoint); it belongs in the GlobusError instead.
    seen = {}
    monkeypatch.setattr(globus.shutil, 'which', lambda _n: '/usr/bin/globus')
    monkeypatch.setattr(globus.subprocess, 'run',
                        lambda argv, **kw: seen.update(kw) or _Fake(stdout=''))
    globus._run(['ls', 'EP:/'])
    assert seen['stderr'] is subprocess.PIPE


def test_cli_error_is_wrapped(monkeypatch):
    monkeypatch.setattr(globus.shutil, 'which', lambda _n: '/usr/bin/globus')
    monkeypatch.delenv(globus.LOCAL_ENDPOINT_ENV, raising=False)
    monkeypatch.setattr(gcp_install, 'load_endpoint_state', lambda **kw: None)

    def boom(argv, **kw):
        raise subprocess.CalledProcessError(1, argv, stderr='permission denied')

    monkeypatch.setattr(globus.subprocess, 'run', boom)
    with pytest.raises(globus.GlobusError, match='permission denied'):
        globus.local_endpoint_id()


# ----------------------------------------------------------------------
# restrict-paths sharing check
# ----------------------------------------------------------------------
def test_working_is_shared_hit(tmp_path):
    ok, reason = globus.working_is_shared(str(tmp_path / 'stage'),
                                          rules=[f'rw{tmp_path}', 'rw/other'])
    assert ok and reason is None


def test_working_is_shared_miss(tmp_path):
    ok, reason = globus.working_is_shared(str(tmp_path / 'stage'),
                                          rules=['rw/somewhere/else'])
    assert not ok
    assert 'not under any path' in reason


def test_working_is_shared_unknown_when_no_state(monkeypatch, tmp_path):
    monkeypatch.setattr(gcp_install, 'load_endpoint_state', lambda **kw: None)
    ok, reason = globus.working_is_shared(str(tmp_path))
    assert ok and reason is None


def test_working_is_shared_reads_state(monkeypatch, tmp_path):
    monkeypatch.setattr(gcp_install, 'load_endpoint_state',
                        lambda **kw: {'endpoint_id': 'EP',
                                      'restrict_paths': [f'rw{tmp_path}']})
    ok, _ = globus.working_is_shared(str(tmp_path / 'stage'))
    assert ok


# ----------------------------------------------------------------------
# transport push/pull globus branch
# ----------------------------------------------------------------------
def test_push_to_globus(monkeypatch, tmp_path):
    calls = {}
    monkeypatch.setattr(transport, 'ensure_endpoint', lambda wd, **k: 'LOCAL-EP')
    monkeypatch.setattr(globus, 'transfer',
                        lambda src, dst, label=None: calls.update(src=src, dst=dst, label=label))
    dest = transport.parse_endpoint('globus:COLL-ID:/incoming/sub')
    transport.push(str(tmp_path), dest)
    assert calls['src'] == f'LOCAL-EP:{os.path.realpath(str(tmp_path))}'  # realpath'd
    assert calls['dst'] == 'COLL-ID:/incoming/sub'


def test_push_threads_globus_options(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(transport, 'ensure_endpoint',
                        lambda wd, **k: seen.update(k) or 'EP')
    monkeypatch.setattr(globus, 'transfer', lambda *a, **k: None)
    dest = transport.parse_endpoint('globus:COLL:/p')
    opts = {'endpoint_id': 'PINNED', 'config_dir': '/c', 'name': 'nm', 'auto_install': True}
    transport.push(str(tmp_path), dest, globus=opts)
    assert seen == opts  # every knob reaches ensure_endpoint


def test_pull_threads_globus_options(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(transport, 'ensure_endpoint',
                        lambda wd, **k: seen.update(k) or 'EP')
    monkeypatch.setattr(globus, 'transfer', lambda *a, **k: None)
    src = transport.parse_endpoint('globus:COLL:/p')
    opts = {'endpoint_id': None, 'config_dir': None, 'name': None, 'auto_install': None}
    transport.pull(src, str(tmp_path / 'w'), globus=opts)
    assert seen == opts


def test_cli_parses_globus_flags():
    from crypt4gh.pack import cli
    p = cli._build_parser('pack')
    args = p.parse_args(['--recipient_pk', 'x.pub', '--install-gcp',
                         '--globus-endpoint', 'EP', '--globus-config-dir', '/c',
                         '--globus-endpoint-name', 'nm', 'srcd', 'dstd'])
    assert args.install_gcp is True
    assert (args.globus_endpoint, args.globus_config_dir, args.globus_endpoint_name) \
        == ('EP', '/c', 'nm')


def test_cli_globus_flags_default_off():
    from crypt4gh.pack import cli
    args = cli._build_parser('unpack').parse_args(['srcd', 'dstd'])
    assert args.install_gcp is False
    assert args.globus_endpoint is None and args.globus_config_dir is None


def test_pull_from_globus(monkeypatch, tmp_path):
    calls = {}
    monkeypatch.setattr(transport, 'ensure_endpoint', lambda wd, **k: 'LOCAL-EP')
    monkeypatch.setattr(globus, 'transfer',
                        lambda src, dst, label=None: calls.update(src=src, dst=dst))
    src = transport.parse_endpoint('globus:COLL-ID:/data')
    work = tmp_path / 'work'
    work.mkdir()
    transport.pull(src, str(work))
    assert calls['src'] == 'COLL-ID:/data'
    assert calls['dst'] == f'LOCAL-EP:{os.path.realpath(str(work))}'


# ----------------------------------------------------------------------
# transport.ensure_endpoint: C -> B -> A orchestration (branch matrix)
# ----------------------------------------------------------------------
@pytest.fixture
def ep(monkeypatch):
    """Mock the gcp_install/globus surface ensure_endpoint drives; record calls."""
    rec = {'started': 0, 'shared': 0, 'installed': 0}
    monkeypatch.setattr(globus, 'resolve_local_endpoint', lambda: ('EP', '/cfg'))
    monkeypatch.setattr(gcp_install, 'find_on_path', lambda name=None: '/bin/gcp')
    monkeypatch.setattr(gcp_install, 'current_restrict_paths', lambda **k: ['rw~/'])
    monkeypatch.setattr(gcp_install, 'ensure_path_shared',
                        lambda *a, **k: rec.update(shared=rec['shared'] + 1) or False)
    monkeypatch.setattr(gcp_install, 'start',
                        lambda *a, **k: rec.update(started=rec['started'] + 1))
    monkeypatch.setattr(gcp_install, 'ensure_usable',
                        lambda **k: rec.update(installed=rec['installed'] + 1) or ('/bin/gcp', 'NEW-EP'))
    monkeypatch.setattr(globus, 'working_is_shared', lambda wd: (True, None))
    monkeypatch.delenv(transport.GLOBUS_AUTO_INSTALL_ENV, raising=False)
    return rec


def test_ensure_endpoint_already_shared_starts_if_needed(ep):
    # ensure_path_shared returns False (covered) -> we still call start (a no-op
    # when connected), and never auto-install.
    assert transport.ensure_endpoint('/work') == 'EP'
    assert ep == {'started': 1, 'shared': 1, 'installed': 0}


def test_ensure_endpoint_unshared_shares_and_skips_start(monkeypatch, ep):
    # A restart (ensure_path_shared True) also brings it up, so no separate start.
    monkeypatch.setattr(gcp_install, 'ensure_path_shared',
                        lambda *a, **k: ep.update(shared=ep['shared'] + 1) or True)
    assert transport.ensure_endpoint('/work') == 'EP'
    assert ep['shared'] == 1 and ep['started'] == 0


def test_ensure_endpoint_absent_autoinstall(monkeypatch, ep):
    monkeypatch.setattr(globus, 'resolve_local_endpoint',
                        lambda: (_ for _ in ()).throw(globus.GlobusError('none')))
    # After install, ensure_usable returns the new id directly.
    assert transport.ensure_endpoint('/work', auto_install=True) == 'NEW-EP'
    assert ep['installed'] == 1


def test_ensure_endpoint_autoinstall_reresolves_when_usable_returns_none(monkeypatch, ep):
    # ensure_usable returns id=None when it finds a pre-existing connected
    # endpoint; ensure_endpoint then re-resolves via the (now-written) state file.
    ids = iter([globus.GlobusError('none'), ('RE-EP', '/cfg')])

    def resolve():
        val = next(ids)
        if isinstance(val, Exception):
            raise val
        return val

    monkeypatch.setattr(globus, 'resolve_local_endpoint', resolve)
    monkeypatch.setattr(gcp_install, 'ensure_usable',
                        lambda **k: ep.update(installed=ep['installed'] + 1) or ('/bin/gcp', None))
    assert transport.ensure_endpoint('/work', auto_install=True) == 'RE-EP'
    assert ep['installed'] == 1


def test_ensure_endpoint_absent_no_autoinstall_errors(monkeypatch, ep):
    monkeypatch.setattr(globus, 'resolve_local_endpoint',
                        lambda: (_ for _ in ()).throw(globus.GlobusError('none')))
    with pytest.raises(globus.GlobusError, match='no local Globus endpoint'):
        transport.ensure_endpoint('/work', auto_install=False)


def test_ensure_endpoint_autoinstall_from_env(monkeypatch, ep):
    monkeypatch.setattr(globus, 'resolve_local_endpoint',
                        lambda: (_ for _ in ()).throw(globus.GlobusError('none')))
    monkeypatch.setenv(transport.GLOBUS_AUTO_INSTALL_ENV, '1')
    assert transport.ensure_endpoint('/work') == 'NEW-EP'  # env opts into C


def test_ensure_endpoint_verifies_reachability(monkeypatch, ep):
    # ensure_endpoint must hand start/ensure_path_shared a verify() that probes
    # the transfer API, so a transfer is not issued during the GCDisconnected lag.
    reached = []
    monkeypatch.setattr(globus, 'endpoint_reachable',
                        lambda eid: reached.append(eid) or True)
    monkeypatch.setattr(gcp_install, 'ensure_path_shared',
                        lambda *a, verify=None, **k: bool(verify and verify()))
    transport.ensure_endpoint('/work')
    assert reached == ['EP']  # verify was actually invoked with the resolved id


def test_ensure_endpoint_no_local_launcher_warns_only(monkeypatch, ep):
    # A managed collection / DTN: endpoint resolves but nothing to run locally.
    monkeypatch.setattr(gcp_install, 'find_on_path', lambda name=None: None)
    warned = []
    monkeypatch.setattr(globus, 'working_is_shared', lambda wd: (False, 'not shared'))
    monkeypatch.setattr(transport.LOG, 'warning', lambda *a, **k: warned.append(a))
    assert transport.ensure_endpoint('/work') == 'EP'
    assert ep['started'] == 0 and ep['shared'] == 0 and warned


@pytest.mark.parametrize('exc, rc, text', [
    (globus.GlobusError('502 GCDisconnected'), 1, 'pack: 502 GCDisconnected'),
    (gcp_install.InstallError('endpoint gone'), 1, 'pack: endpoint gone'),
    (KeyboardInterrupt(), 130, 'pack: interrupted'),
])
def test_cli_reports_globus_failures_without_traceback(monkeypatch, capsys, tmp_path,
                                                       exc, rc, text):
    from crypt4gh.pack import cli, api

    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(api, 'pack', boom)
    monkeypatch.setattr(cli, '_load_seckey', lambda *a, **k: b'k' * 32)
    monkeypatch.setattr(cli, '_load_pubkey', lambda p: b'p' * 32)
    with pytest.raises(SystemExit) as e:
        cli.main(['pack', '--recipient_pk', 'x.pub', str(tmp_path), 'globus:C:/p'])
    assert e.value.code == rc
    assert text in capsys.readouterr().err
