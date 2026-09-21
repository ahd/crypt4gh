# -*- coding: utf-8 -*-
"""Streaming compression codecs used between tarring and encryption.

Codecs are shelled out to the standard command-line tools (``gzip``, ``bzip2``,
``zstd``) rather than done in-process: that keeps the whole tar -> compress ->
encrypt path a bounded-memory stream, and lets ``zstd`` use every core
(``-T0``) which matters at petabyte scale.  ``none`` is the default; genomic
payloads (BAM/CRAM/VCF.gz) are usually already compressed.
"""

import shutil

# codec name -> compressor binary
_BINARY = {
    'gzip':  'gzip',
    'bzip2': 'bzip2',
    'zstd':  'zstd',
}

VALID_CODECS = ('none', 'gzip', 'bzip2', 'zstd')


def parse_codec(spec):
    """Parse a ``--compress`` value such as ``gzip``, ``bzip2:1`` or ``zstd:19``.

    :returns: ``(name, level)`` where ``level`` is an ``int`` or ``None``.
    """
    if spec is None:
        return ('none', None)
    name, _, level = spec.partition(':')
    name = name.strip().lower()
    if name not in VALID_CODECS:
        raise ValueError(f'Unsupported codec {name!r}; choose from {", ".join(VALID_CODECS)}')
    if level == '':
        return (name, None)
    if name == 'none':
        raise ValueError("Codec 'none' does not take a level")
    try:
        return (name, int(level))
    except ValueError:
        raise ValueError(f'Invalid compression level {level!r} for {name}')


def ensure_available(name):
    """Raise if the codec's command-line tool is not on PATH."""
    if name == 'none':
        return
    binary = _BINARY[name]
    if shutil.which(binary) is None:
        raise ValueError(f'Compression codec {name!r} requires the {binary!r} command, which was not found on PATH')


def compressor_argv(name, level=None):
    """argv that reads plaintext on stdin and writes compressed data to stdout.

    Returns ``None`` for the ``none`` codec (no subprocess needed).
    """
    if name == 'none':
        return None
    if name == 'gzip':
        argv = ['gzip', '-c']
    elif name == 'bzip2':
        argv = ['bzip2', '-c']
    elif name == 'zstd':
        argv = ['zstd', '-q', '-c', '-T0']
    else:  # pragma: no cover - guarded by parse_codec
        raise ValueError(f'Unsupported codec {name!r}')
    if level is not None:
        argv.append(f'-{level}')
    return argv


def decompressor_argv(name):
    """argv that reads compressed data on stdin and writes plaintext to stdout."""
    if name == 'none':
        return None
    if name == 'gzip':
        return ['gzip', '-dc']
    if name == 'bzip2':
        return ['bzip2', '-dc']
    if name == 'zstd':
        return ['zstd', '-dc', '-q']
    raise ValueError(f'Unsupported codec {name!r}')  # pragma: no cover
