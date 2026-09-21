# -*- coding: utf-8 -*-
import os
import subprocess

import pytest

from crypt4gh.pack import codecs


@pytest.mark.parametrize('spec, expected', [
    (None, ('none', None)),
    ('none', ('none', None)),
    ('gzip', ('gzip', None)),
    ('gzip:9', ('gzip', 9)),
    ('bzip2:1', ('bzip2', 1)),
    ('zstd:19', ('zstd', 19)),
    ('ZSTD', ('zstd', None)),
])
def test_parse_codec(spec, expected):
    assert codecs.parse_codec(spec) == expected


@pytest.mark.parametrize('spec', ['lz4', 'gzip:abc', 'none:5'])
def test_parse_codec_invalid(spec):
    with pytest.raises(ValueError):
        codecs.parse_codec(spec)


def test_none_has_no_argv():
    assert codecs.compressor_argv('none') is None
    assert codecs.decompressor_argv('none') is None


@pytest.mark.parametrize('name', ['gzip', 'bzip2', 'zstd'])
def test_compress_decompress_roundtrip(name):
    data = os.urandom(200_000)
    comp = subprocess.run(codecs.compressor_argv(name, level=1), input=data,
                          stdout=subprocess.PIPE, check=True).stdout
    back = subprocess.run(codecs.decompressor_argv(name), input=comp,
                          stdout=subprocess.PIPE, check=True).stdout
    assert back == data


def test_ensure_available_none_is_noop():
    codecs.ensure_available('none')  # must not raise
