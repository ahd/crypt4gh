# -*- coding: utf-8 -*-
"""--log / C4GH_LOG for pack/unpack: the run, its pool workers, directory and
transport operations all reach the configured destination."""

import json
import logging

import pytest

from crypt4gh.pack import cli, logsetup


@pytest.fixture(autouse=True)
def _reset_logging():
    yield
    root = logging.getLogger()
    for h in [h for h in root.handlers if getattr(h, '_c4gh', False)]:
        root.removeHandler(h)
        h.close()


@pytest.fixture
def run(monkeypatch, alice, bob):
    """Run the pack/unpack CLI with raw test keys (no key files)."""
    monkeypatch.setattr(cli, '_load_seckey', lambda *a, **k: alice['sk'])
    monkeypatch.setattr(cli, '_load_pubkey', lambda p: bob['pk'])
    monkeypatch.delenv('C4GH_DEBUG', raising=False)
    return cli.main


def test_log_file_gets_run_directory_and_worker_records(run, sample_tree, tmp_path):
    log = tmp_path / 'run.log'
    run(['pack', '-vv', '-j', '2', '--log', str(log), '--recipient_pk', 'x.pub',
         str(sample_tree), str(tmp_path / 'out')])
    text = log.read_text()
    assert 'pack ' in text and 'Walked' in text                 # run + directory walk
    assert 'Packed sub1/deep/rand.bin' in text                  # per-item, from a worker
    worker_lines = [l for l in text.splitlines()
                    if 'Packed ' in l and ' MainProcess ' not in l]
    assert worker_lines, 'pool workers must log to --log too'
    assert 'pack: 9 item(s) done, 0 error(s)' in text           # the outcome


def test_log_file_is_info_even_when_terminal_is_quiet(run, sample_tree, tmp_path, capsys):
    log = tmp_path / 'run.log'
    run(['pack', '--log', str(log), '--recipient_pk', 'x.pub',
         str(sample_tree), str(tmp_path / 'out')])
    text = log.read_text()
    assert 'Walked' in text and 'Packing 4 item(s)' in text
    assert 'Packed ' not in text                                # DEBUG needs -vv
    assert capsys.readouterr().err.strip() == 'pack: 9 item(s) done, 0 error(s)'


def test_log_appends(run, sample_tree, tmp_path):
    log = tmp_path / 'run.log'
    log.write_text('earlier line\n')
    run(['pack', '--log', str(log), '--recipient_pk', 'x.pub',
         str(sample_tree), str(tmp_path / 'out')])
    assert log.read_text().startswith('earlier line\n')


def test_c4gh_log_env_is_the_default(run, monkeypatch, sample_tree, tmp_path):
    log = tmp_path / 'env.log'
    monkeypatch.setenv('C4GH_LOG', str(log))
    run(['pack', '--recipient_pk', 'x.pub', str(sample_tree), str(tmp_path / 'out')])
    assert 'Walked' in log.read_text()


def test_log_accepts_a_dictconfig_document(run, sample_tree, tmp_path):
    # The same contract as `crypt4gh --log` for the streaming verbs.
    target = tmp_path / 'via-config.log'
    config = tmp_path / 'logging.json'
    config.write_text(json.dumps({
        'version': 1,
        'disable_existing_loggers': False,
        'handlers': {'f': {'class': 'logging.FileHandler', 'filename': str(target),
                           'level': 'INFO'}},
        'loggers': {'crypt4gh': {'handlers': ['f'], 'level': 'INFO'}},
    }))
    run(['pack', '--log', str(config), '--recipient_pk', 'x.pub',
         str(sample_tree), str(tmp_path / 'out')])
    assert 'Walked' in target.read_text()
    assert 'Walked' not in config.read_text()                   # not appended to


def test_failure_is_logged_once_on_terminal(run, tmp_path, capsys):
    log = tmp_path / 'run.log'
    with pytest.raises(SystemExit):
        run(['pack', '-v', '--log', str(log), '--recipient_pk', 'x.pub',
             str(tmp_path / 'missing'), str(tmp_path / 'out')])
    assert 'pack failed: Source directory not found' in log.read_text()
    err = capsys.readouterr().err
    assert err.count('Source directory not found') == 1         # printed, not also logged


def test_worker_init_reapplies_parent_config(tmp_path):
    log = tmp_path / 'w.log'
    logsetup.configure(0, str(log))
    cfg = logsetup.current()
    logsetup.worker_init(cfg)                                   # idempotent, no stacking
    ours = [h for h in logging.getLogger().handlers if getattr(h, '_c4gh', False)]
    assert len(ours) == 2                                       # terminal + file
    logging.getLogger('crypt4gh.test').info('hello')
    assert log.read_text().count('hello') == 1


def test_globus_and_gcp_records_reach_the_log_file(tmp_path):
    from crypt4gh.pack import gcp_install, globus, transport
    log = tmp_path / 'g.log'
    logsetup.configure(0, str(log))
    for mod in (globus, gcp_install, transport):
        mod.LOG.info('from %s', mod.__name__)
    text = log.read_text()
    for name in ('crypt4gh.pack.globus', 'crypt4gh.pack.gcp_install', 'crypt4gh.pack.transport'):
        assert f'from {name}' in text
