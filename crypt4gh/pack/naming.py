# -*- coding: utf-8 -*-
"""Plaintext <-> ciphertext name conventions.

Pack output is *self-describing* through its suffix chain, so :func:`unpack` can
reconstruct intent from filenames alone even when the SQLite catalog is absent.
The catalog remains the authoritative record (it also carries empty
directories, symlinks and permission bits, which filenames cannot).

    file    a/b/c.txt                 ->  a/b/c.txt.c4gh
    tar     a/         (no compress)  ->  a.tar.c4gh
    tar     a/         (gzip)         ->  a.tar.gz.c4gh
    tar     a/         (bzip2)        ->  a.tar.bz2.c4gh
    tar     a/         (zstd)         ->  a.tar.zst.c4gh
"""

CRYPT4GH_EXT = '.c4gh'

# codec name  <->  tar suffix
_CODEC_TO_SUFFIX = {
    'none':  '',
    'gzip':  '.gz',
    'bzip2': '.bz2',
    'zstd':  '.zst',
}
_SUFFIX_TO_CODEC = {v: k for k, v in _CODEC_TO_SUFFIX.items() if v}


def codec_suffix(codec):
    """Return the tar filename suffix for a codec name (``''`` for ``none``)."""
    try:
        return _CODEC_TO_SUFFIX[codec]
    except KeyError:
        raise ValueError(f'Unknown codec: {codec}')


def cipher_name(relpath, kind, codec='none'):
    """Map a source-relative path to its ciphertext-relative path.

    :param relpath: source path relative to the source root (POSIX separators).
    :param kind: ``'file'`` or ``'tar'``.
    :param codec: compression codec name (only meaningful for ``'tar'``).
    """
    if kind == 'file':
        return relpath + CRYPT4GH_EXT
    if kind == 'tar':
        return relpath + '.tar' + codec_suffix(codec) + CRYPT4GH_EXT
    raise ValueError(f'Cannot name a {kind!r} item')


def parse_cipher_name(cipher_relpath):
    """Inverse of :func:`cipher_name`.

    :returns: ``(orig_relpath, kind, codec)``.
    :raises ValueError: if the name does not end in ``.c4gh``.
    """
    if not cipher_relpath.endswith(CRYPT4GH_EXT):
        raise ValueError(f'Not a Crypt4GH file: {cipher_relpath}')

    rest = cipher_relpath[:-len(CRYPT4GH_EXT)]

    # Longest codec suffixes first so '.tar.gz' wins over a bare '.tar'.
    for suffix, codec in sorted(_SUFFIX_TO_CODEC.items(), key=lambda kv: -len(kv[0])):
        if rest.endswith('.tar' + suffix):
            return rest[:-len('.tar' + suffix)], 'tar', codec
    if rest.endswith('.tar'):
        return rest[:-len('.tar')], 'tar', 'none'

    return rest, 'file', 'none'
