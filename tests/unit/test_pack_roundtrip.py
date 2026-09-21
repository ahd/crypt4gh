# -*- coding: utf-8 -*-
import os
import glob
import stat

import pytest

from crypt4gh.pack import api
from treecmp import assert_trees_equal


@pytest.mark.parametrize('tar', [False, True])
@pytest.mark.parametrize('codec', ['none', 'gzip', 'bzip2', 'zstd'])
def test_roundtrip(sample_tree, tmp_path, alice, bob, tar, codec):
    if codec != 'none' and not tar:
        pytest.skip('compression only applies with --tar')
    enc, dec = tmp_path / 'enc', tmp_path / 'dec'
    api.pack(str(sample_tree), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']],
             tar=tar, compress=codec, jobs=1)
    api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=1)
    assert_trees_equal(sample_tree, dec)


def test_roundtrip_multiprocess(sample_tree, tmp_path, alice, bob):
    enc, dec = tmp_path / 'enc', tmp_path / 'dec'
    api.pack(str(sample_tree), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']], jobs=2)
    api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=2)
    assert_trees_equal(sample_tree, dec)


def test_mirror_preserves_mode_and_mtime(sample_tree, tmp_path, alice, bob):
    os.utime(sample_tree / 'root.txt', (1_000_000, 1_234_567))
    enc, dec = tmp_path / 'enc', tmp_path / 'dec'
    api.pack(str(sample_tree), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']], jobs=1)
    api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=1)
    assert int(os.stat(dec / 'root.txt').st_mtime) == 1_234_567
    assert stat.S_IMODE(os.lstat(dec / 'sub1' / 'a.txt').st_mode) == 0o640


def test_multiple_recipients(sample_tree, tmp_path, alice, bob):
    """A file packed for two recipients decrypts for either."""
    enc = tmp_path / 'enc'
    api.pack(str(sample_tree), str(enc), seckey=bob['sk'],
             recipient_pubkeys=[alice['pk'], bob['pk']], jobs=1)
    for who in (alice, bob):
        dec = tmp_path / f'dec_{id(who)}'
        api.unpack(str(enc), str(dec), seckey=who['sk'], jobs=1)
        assert_trees_equal(sample_tree, dec)


def test_corruption_is_detected(sample_tree, tmp_path, alice, bob):
    enc = tmp_path / 'enc'
    api.pack(str(sample_tree), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']], jobs=1)
    target = enc / 'sub1' / 'deep' / 'rand.bin.c4gh'
    blob = bytearray(target.read_bytes())
    blob[-1] ^= 0xFF                      # flip a byte in the last segment's MAC
    target.write_bytes(blob)
    with pytest.raises(ValueError):
        api.unpack(str(enc), str(tmp_path / 'dec'), seckey=alice['sk'], jobs=1)


def test_unpack_without_catalog(sample_tree, tmp_path, alice, bob):
    enc, dec = tmp_path / 'enc', tmp_path / 'dec'
    api.pack(str(sample_tree), str(enc), seckey=bob['sk'], recipient_pubkeys=[alice['pk']], jobs=1)
    for f in glob.glob(str(enc / 'catalog.sqlite*')):
        os.remove(f)
    api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=1)
    # Regular files are restored from filenames alone...
    assert (dec / 'root.txt').read_text() == 'file at root\n'
    assert (dec / 'sub1' / 'a.txt').read_text() == 'hello from sub1\n'
    # ...but symlinks/empty dirs are not (documented limitation).
    assert not (dec / 'sub1' / 'link_to_b').exists()


def test_compress_requires_tar(sample_tree, tmp_path, alice, bob):
    with pytest.raises(ValueError, match='requires --tar'):
        api.pack(str(sample_tree), str(tmp_path / 'enc'), seckey=bob['sk'],
                 recipient_pubkeys=[alice['pk']], tar=False, compress='gzip', jobs=1)


def test_both_remote_rejected():
    with pytest.raises(ValueError, match='remote'):
        api.pack('h1:/a', 'h2:/b', seckey=b'0' * 32, recipient_pubkeys=[b'1' * 32], jobs=1)
