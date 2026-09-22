# -*- coding: utf-8 -*-
import subprocess

import pytest

from crypt4gh.pack import transport, globus


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
        return _Fake(stdout='')

    monkeypatch.setattr(globus.subprocess, 'run', fake_run)
    monkeypatch.delenv(globus.LOCAL_ENDPOINT_ENV, raising=False)
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


def test_wait_builds_argv(cli):
    globus.wait('TASK-9', polling_interval=5, timeout=60)
    argv = cli[0]
    assert argv[1:3] == ['task', 'wait'] and argv[3] == 'TASK-9'
    assert argv[argv.index('--polling-interval') + 1] == '5'
    assert argv[argv.index('--timeout') + 1] == '60'


def test_transfer_submits_then_waits(cli):
    globus.transfer('SRC:/a', 'DST:/b')
    verbs = [c[1] for c in cli]
    assert verbs == ['transfer', 'task']  # submit, then wait


def test_cli_error_is_wrapped(monkeypatch):
    monkeypatch.setattr(globus.shutil, 'which', lambda _n: '/usr/bin/globus')

    def boom(argv, **kw):
        raise subprocess.CalledProcessError(1, argv, stderr='permission denied')

    monkeypatch.setattr(globus.subprocess, 'run', boom)
    with pytest.raises(globus.GlobusError, match='permission denied'):
        globus.local_endpoint_id()


# ----------------------------------------------------------------------
# config-paths sharing check
# ----------------------------------------------------------------------
def test_working_is_shared_hit(tmp_path):
    cfg = tmp_path / 'config-paths'
    cfg.write_text(f'{tmp_path}/,0,1\n/other,0,1\n')
    ok, reason = globus.working_is_shared(str(tmp_path / 'stage'), config_paths=str(cfg))
    assert ok and reason is None


def test_working_is_shared_miss(tmp_path):
    cfg = tmp_path / 'config-paths'
    cfg.write_text('/somewhere/else,0,1\n')
    ok, reason = globus.working_is_shared(str(tmp_path / 'stage'), config_paths=str(cfg))
    assert not ok
    assert 'not under any path' in reason


def test_working_is_shared_unknown_when_no_config(tmp_path):
    ok, reason = globus.working_is_shared(str(tmp_path), config_paths=str(tmp_path / 'nope'))
    assert ok and reason is None


# ----------------------------------------------------------------------
# transport push/pull globus branch
# ----------------------------------------------------------------------
def test_push_to_globus(monkeypatch, tmp_path):
    calls = {}
    monkeypatch.setattr(transport, 'LOG', transport.LOG)
    monkeypatch.setattr(globus, 'local_endpoint_id', lambda: 'LOCAL-EP')
    monkeypatch.setattr(globus, 'working_is_shared', lambda wd: (True, None))
    monkeypatch.setattr(globus, 'transfer',
                        lambda src, dst, label=None: calls.update(src=src, dst=dst, label=label))
    dest = transport.parse_endpoint('globus:COLL-ID:/incoming/sub')
    transport.push(str(tmp_path), dest)
    assert calls['src'] == f'LOCAL-EP:{tmp_path}'
    assert calls['dst'] == 'COLL-ID:/incoming/sub'


def test_pull_from_globus(monkeypatch, tmp_path):
    calls = {}
    monkeypatch.setattr(globus, 'local_endpoint_id', lambda: 'LOCAL-EP')
    monkeypatch.setattr(globus, 'working_is_shared', lambda wd: (True, None))
    monkeypatch.setattr(globus, 'transfer',
                        lambda src, dst, label=None: calls.update(src=src, dst=dst))
    src = transport.parse_endpoint('globus:COLL-ID:/data')
    work = tmp_path / 'work'
    transport.pull(src, str(work))
    assert calls['src'] == 'COLL-ID:/data'
    assert calls['dst'] == f'LOCAL-EP:{work}'
