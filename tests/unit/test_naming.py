# -*- coding: utf-8 -*-
import pytest

from crypt4gh.pack import naming


@pytest.mark.parametrize('relpath, kind, codec, expected', [
    ('a/b/c.txt', 'file', 'none', 'a/b/c.txt.c4gh'),
    ('a', 'tar', 'none', 'a.tar.c4gh'),
    ('a', 'tar', 'gzip', 'a.tar.gz.c4gh'),
    ('a', 'tar', 'bzip2', 'a.tar.bz2.c4gh'),
    ('a', 'tar', 'zstd', 'a.tar.zst.c4gh'),
])
def test_cipher_name(relpath, kind, codec, expected):
    assert naming.cipher_name(relpath, kind, codec) == expected


@pytest.mark.parametrize('relpath, kind, codec', [
    ('a/b/c.txt', 'file', 'none'),
    ('deep/dir.name', 'tar', 'none'),
    ('deep/dir.name', 'tar', 'gzip'),
    ('deep/dir.name', 'tar', 'bzip2'),
    ('deep/dir.name', 'tar', 'zstd'),
])
def test_roundtrip_names(relpath, kind, codec):
    cipher = naming.cipher_name(relpath, kind, codec)
    assert naming.parse_cipher_name(cipher) == (relpath, kind, codec)


def test_name_only_ambiguity_is_documented():
    """A plain file named 'x.tar.gz' is name-indistinguishable from a gzipped
    tarball of dir 'x'. The catalog carries the authoritative kind; only the
    catalog-absent fallback relies on this parse."""
    assert naming.parse_cipher_name('x.tar.gz.c4gh') == ('x', 'tar', 'gzip')


def test_parse_rejects_non_c4gh():
    with pytest.raises(ValueError):
        naming.parse_cipher_name('a/b/c.txt')


def test_unknown_codec():
    with pytest.raises(ValueError):
        naming.cipher_name('a', 'tar', 'lz4')
