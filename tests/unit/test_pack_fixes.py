# -*- coding: utf-8 -*-
"""Regression tests for the review findings, plus previously-uncovered paths."""

import os
import sqlite3
import subprocess

import pytest

from crypt4gh.pack import api, fs, transport
from treecmp import assert_trees_equal


# --- #1: unpack must not mutate the source ciphertext -----------------
def test_unpack_does_not_mutate_source(sample_tree, tmp_path, alice, bob):
    enc, dec = tmp_path / 'enc', tmp_path / 'dec'
    api.pack(str(sample_tree), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']], jobs=1)
    cat = enc / 'catalog.sqlite'
    assert not (enc / 'catalog.sqlite-wal').exists()   # checkpointed on close
    before = cat.read_bytes()

    api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=1)

    assert cat.read_bytes() == before                  # untouched by unpack
    assert not (enc / 'catalog.sqlite-wal').exists()
    assert not (enc / 'catalog.sqlite-shm').exists()
    assert_trees_equal(sample_tree, dec)


def test_unpack_from_readonly_source(sample_tree, tmp_path, alice, bob):
    enc, dec = tmp_path / 'enc', tmp_path / 'dec'
    api.pack(str(sample_tree), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']], jobs=1)

    paths = [enc]
    for root, dirs, files in os.walk(enc):
        paths += [os.path.join(root, d) for d in dirs]
        paths += [os.path.join(root, f) for f in files]
    deep_first = sorted((str(p) for p in paths), key=len, reverse=True)
    try:
        for p in deep_first:
            os.chmod(p, 0o555 if os.path.isdir(p) else 0o444)
        api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=1)  # must not need to write to enc
        assert_trees_equal(sample_tree, dec)
    finally:
        for p in deep_first:
            try:
                os.chmod(p, 0o755 if os.path.isdir(p) else 0o644)
            except OSError:
                pass


# --- #2: catalog stays intact after a real (forked) parallel pack -----
def test_catalog_integrity_after_parallel_pack(tmp_path, alice, bob):
    src = tmp_path / 'many'
    src.mkdir()
    for i in range(60):
        (src / f'f{i:03d}.txt').write_text(f'file number {i}\n')
    enc = tmp_path / 'enc'
    api.pack(str(src), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']], jobs=4)

    db = sqlite3.connect(enc / 'catalog.sqlite')
    try:
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        done = db.execute("SELECT COUNT(*) FROM item WHERE status='done'").fetchone()[0]
        assert done == 60
    finally:
        db.close()


# --- highest-risk gap: multi-segment payloads through the pipeline ----
@pytest.mark.parametrize('tar, codec', [(False, 'none'), (True, 'none'), (True, 'gzip'), (True, 'zstd')])
def test_multisegment_payload(tmp_path, alice, bob, tar, codec):
    src = tmp_path / 'big'
    (src / 'd').mkdir(parents=True)
    (src / 'd' / 'rand.bin').write_bytes(os.urandom(200_000))   # ~3 segments, incompressible
    (src / 'd' / 'zeros.bin').write_bytes(b'\0' * 300_000)      # compressible, multi-segment
    enc, dec = tmp_path / 'enc', tmp_path / 'dec'
    api.pack(str(src), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']],
             tar=tar, compress=codec, jobs=1)
    api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=1)
    assert_trees_equal(src, dec)


# --- coverage: RemoteFS find-output parsing (no ssh needed) -----------
def test_remotefs_find_parsing(monkeypatch):
    ep = transport.parse_endpoint('host:/data')
    r = fs.RemoteFS(ep)
    canned = (
        "d\t755\t100.0\t4096\t\t\n"                 # the root '.'
        "d\t750\t100.0\t4096\tsub\t\n"
        "f\t644\t101.5\t12\tsub/a.txt\t\n"
        "l\t777\t102.0\t7\tsub/link\t../a.txt\n"
    )

    class FakeProc:
        returncode = 0
        def communicate(self):
            return (canned, '')

    monkeypatch.setattr(fs.RemoteFS, '_ssh', lambda self, cmd, **kw: FakeProc())
    by = {e['relpath']: e for e in r._find(maxdepth=None)}
    assert by['sub']['kind'] == 'dir' and by['sub']['src_mode'] == 0o750
    assert by['sub/a.txt']['kind'] == 'file' and by['sub/a.txt']['src_mode'] == 0o644
    assert by['sub/a.txt']['src_size'] == 12
    assert by['sub/link']['kind'] == 'symlink' and by['sub/link']['symlink_target'] == '../a.txt'


# --- coverage: transport local push/pull round-trip -------------------
def test_transport_local_push_pull(tmp_path):
    src = tmp_path / 'a'
    src.mkdir()
    (src / 'f.txt').write_text('payload')
    (src / 'sub').mkdir()
    (src / 'sub' / 'g.txt').write_text('nested')

    transport.push(str(src), transport.parse_endpoint(str(tmp_path / 'b')))
    assert (tmp_path / 'b' / 'f.txt').read_text() == 'payload'
    assert (tmp_path / 'b' / 'sub' / 'g.txt').read_text() == 'nested'

    transport.pull(transport.parse_endpoint(str(tmp_path / 'b')), str(tmp_path / 'w'))
    assert (tmp_path / 'w' / 'f.txt').read_text() == 'payload'


# --- coverage: symlink-to-directory in mirror mode --------------------
def test_symlink_to_dir_roundtrip(tmp_path, alice, bob):
    src = tmp_path / 's'
    (src / 'real').mkdir(parents=True)
    (src / 'real' / 'x.txt').write_text('x')
    os.symlink('real', src / 'linkdir')
    enc, dec = tmp_path / 'e', tmp_path / 'd'
    api.pack(str(src), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']], jobs=1)
    api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=1)
    assert os.path.islink(dec / 'linkdir')
    assert os.readlink(dec / 'linkdir') == 'real'
    assert_trees_equal(src, dec)


# --- coverage: directory mode + mtime restoration ---------------------
def test_dir_mode_and_mtime_restored(sample_tree, tmp_path, alice, bob):
    os.chmod(sample_tree / 'sub2', 0o750)
    os.utime(sample_tree / 'sub2', (1_000_000, 1_222_333))
    enc, dec = tmp_path / 'enc', tmp_path / 'dec'
    api.pack(str(sample_tree), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']], jobs=1)
    api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=1)
    import stat
    assert stat.S_IMODE(os.lstat(dec / 'sub2').st_mode) == 0o750
    assert int(os.stat(dec / 'sub2').st_mtime) == 1_222_333


# --- coverage: wrong recipient cannot unpack --------------------------
def test_wrong_recipient_fails(sample_tree, tmp_path, alice, bob):
    enc = tmp_path / 'enc'
    api.pack(str(sample_tree), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']], jobs=1)
    charlie_sk = os.urandom(32)
    with pytest.raises(ValueError):
        api.unpack(str(enc), str(tmp_path / 'dec'), seckey=charlie_sk, jobs=1)


# --- #4: CLI reports transport failure cleanly, no traceback ----------
def test_cli_handles_subprocess_error(monkeypatch):
    from crypt4gh.pack import cli
    monkeypatch.setattr(cli, '_load_seckey', lambda *a, **k: b'0' * 32)
    monkeypatch.setattr(cli, '_load_pubkey', lambda p: b'1' * 32)

    def boom(*a, **k):
        raise subprocess.CalledProcessError(1, ['rsync'])

    monkeypatch.setattr(cli.api, 'pack', boom)
    with pytest.raises(SystemExit) as ei:
        cli.main(['pack', '--recipient_pk', 'x', '/src', 'host:/dst'])
    assert ei.value.code == 1
