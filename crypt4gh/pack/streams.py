# -*- coding: utf-8 -*-
"""Thin file-object wrappers that checksum bytes as they flow through.

The crypto engine in :mod:`crypt4gh.lib` reads via ``readinto`` and writes via
``write``; wrapping its input/output lets us compute a SHA-256 and a byte count
in the *same* streaming pass -- no extra read of petabyte-scale data.
"""

import hashlib


class HashingReader:
    """Wrap a readable binary stream, hashing everything read from it."""

    def __init__(self, raw):
        self._raw = raw
        self._hash = hashlib.sha256()
        self.count = 0

    def readinto(self, buf):
        n = self._raw.readinto(buf)
        if n:
            self._hash.update(memoryview(buf)[:n])
            self.count += n
        return n

    def read(self, size=-1):
        data = self._raw.read(size)
        if data:
            self._hash.update(data)
            self.count += len(data)
        return data

    def hexdigest(self):
        return self._hash.hexdigest()


class HashingWriter:
    """Wrap a writable binary stream, hashing everything written to it."""

    def __init__(self, raw):
        self._raw = raw
        self._hash = hashlib.sha256()
        self.count = 0

    def write(self, data):
        n = self._raw.write(data)
        # Some pipe writers return None; assume the whole buffer was consumed.
        written = len(data) if n is None else n
        self._hash.update(data if written == len(data) else data[:written])
        self.count += written
        return n

    def flush(self):
        if hasattr(self._raw, 'flush'):
            self._raw.flush()

    def hexdigest(self):
        return self._hash.hexdigest()
