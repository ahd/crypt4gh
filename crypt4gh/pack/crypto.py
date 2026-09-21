# -*- coding: utf-8 -*-
"""Pluggable crypto boundary for the pack/unpack pipeline.

The pipeline talks to a ``Cryptor`` rather than calling :mod:`crypt4gh.lib`
directly.  Today the only implementation is :class:`LocalCryptor`, which runs
the existing streaming engine in-process.  A future ``RemoteCryptor`` could run
crypt4gh on the machine that holds the plaintext (encrypt-at-source), so that
only ciphertext ever crosses an untrusted transport such as Globus -- without
the pipeline changing.
"""

from .. import lib


class Cryptor:
    """Interface: transform one plaintext stream <-> one ciphertext stream."""

    def encrypt_stream(self, infile, outfile):
        raise NotImplementedError

    def decrypt_stream(self, infile, outfile):
        raise NotImplementedError


class LocalCryptor(Cryptor):
    """Encrypt/decrypt locally with :mod:`crypt4gh.lib`.

    :param seckey: our 32-byte Curve25519 secret key.
    :param recipient_pubkeys: iterable of recipient public keys (encrypt only).
    :param sender_pubkey: optional expected sender key to verify (decrypt only).
    """

    def __init__(self, seckey, recipient_pubkeys=(), sender_pubkey=None):
        self.seckey = seckey
        # crypt4gh key tuples: (method=0, seckey, recipient_pubkey)
        self.recipient_keys = {(0, seckey, pk) for pk in recipient_pubkeys}
        self.decrypt_keys = [(0, seckey, None)]
        self.sender_pubkey = sender_pubkey

    def encrypt_stream(self, infile, outfile):
        if not self.recipient_keys:
            raise ValueError('No recipient public keys provided for encryption')
        lib.encrypt(self.recipient_keys, infile, outfile)

    def decrypt_stream(self, infile, outfile):
        lib.decrypt(self.decrypt_keys, infile, outfile, sender_pubkey=self.sender_pubkey)
