# -*- coding: utf-8 -*-
import io
import os

import pytest

from crypt4gh.keys import kdf, c4gh


# ---- KDFs ------------------------------------------------------------
@pytest.mark.parametrize('alg, rounds', [
    (b'scrypt', 0),
    (b'bcrypt', 100),
    (b'pbkdf2_hmac_sha256', 1000),
])
def test_derive_key_len_and_determinism(alg, rounds):
    if alg == b'scrypt' and not kdf.scrypt_supported:
        pytest.skip('scrypt not supported on this platform')
    salt = os.urandom(16)
    k1 = kdf.derive_key(alg, b'passphrase', salt, rounds)
    k2 = kdf.derive_key(alg, b'passphrase', salt, rounds)
    assert len(k1) == 32
    assert k1 == k2
    # Different salt -> different key
    assert kdf.derive_key(alg, b'passphrase', os.urandom(16), rounds) != k1


# ---- Crypt4GH private key format -------------------------------------
def _parse(blob, callback=None):
    stream = io.BytesIO(blob)
    stream.read(len(c4gh.MAGIC_WORD))  # get_private_key consumes the magic word first
    return c4gh.parse_private_key(stream, callback)


def test_c4gh_key_roundtrip_unencrypted():
    sk = os.urandom(32)
    blob = c4gh.encode_private_key(sk, passphrase=None, comment=None)
    assert blob.startswith(c4gh.MAGIC_WORD)
    assert _parse(blob) == sk


def test_c4gh_key_roundtrip_encrypted():
    sk = os.urandom(32)
    blob = c4gh.encode_private_key(sk, passphrase=b'hunter2', comment=b'a comment')
    assert _parse(blob, callback=lambda: 'hunter2') == sk


def test_c4gh_wrong_passphrase_exits():
    sk = os.urandom(32)
    blob = c4gh.encode_private_key(sk, passphrase=b'right', comment=None)
    # parse_private_key is decorated to sys.exit(2) on any failure.
    with pytest.raises(SystemExit):
        _parse(blob, callback=lambda: 'wrong')
