# -*- coding: utf-8 -*-
import io
import os

import pytest

from crypt4gh import header, sodium, SEGMENT_SIZE


# ---- validate_edit_list (the fixed latent bug) -----------------------
def test_valid_edit_list_passes():
    header.validate_edit_list([100, 50, 200, 50])  # must not raise


def test_empty_edit_list_ok():
    header.validate_edit_list([])


def test_negative_rejected():
    with pytest.raises(ValueError, match='negative'):
        header.validate_edit_list([-1, 10])


def test_zero_skip_between_reads_rejected():
    with pytest.raises(ValueError, match='0 bytes'):
        header.validate_edit_list([100, 50, 0, 50])


def test_first_block_skipped_rejected():
    with pytest.raises(ValueError, match='First data block'):
        header.validate_edit_list([SEGMENT_SIZE + 1, 10])


def test_whole_block_skip_rejected():
    with pytest.raises(ValueError, match='Data blocks'):
        header.validate_edit_list([100, 50, 2 * SEGMENT_SIZE, 50])


# ---- header packet encrypt/decrypt round-trip ------------------------
def test_header_roundtrip():
    recipient_sk = os.urandom(32)
    recipient_pk = sodium.derive_pk(recipient_sk)
    sender_sk = os.urandom(32)
    sender_pk = sodium.derive_pk(sender_sk)

    session_key = os.urandom(32)
    content = header.make_packet_data_enc(0, session_key)
    packets = list(header.encrypt(content, [(0, sender_sk, recipient_pk)]))
    blob = header.serialize(packets)

    parsed = list(header.parse(io.BytesIO(blob)))
    decrypted, ignored = header.decrypt(parsed, [(0, recipient_sk, None)])
    assert decrypted and not ignored
    data_packets, edit = header.partition_packets(decrypted)
    assert edit is None
    assert [header.parse_enc_packet(p) for p in data_packets] == [session_key]


def test_header_sender_verification():
    recipient_sk = os.urandom(32)
    recipient_pk = sodium.derive_pk(recipient_sk)
    sender_sk = os.urandom(32)
    sender_pk = sodium.derive_pk(sender_sk)

    content = header.make_packet_data_enc(0, os.urandom(32))
    blob = header.serialize(list(header.encrypt(content, [(0, sender_sk, recipient_pk)])))
    parsed = list(header.parse(io.BytesIO(blob)))

    # Correct sender verifies; a wrong sender key makes the packet undecryptable.
    ok, _ = header.decrypt(parsed, [(0, recipient_sk, None)], sender_pubkey=sender_pk)
    assert ok
    bad, ignored = header.decrypt(list(header.parse(io.BytesIO(blob))),
                                  [(0, recipient_sk, None)], sender_pubkey=os.urandom(32))
    assert not bad and ignored
