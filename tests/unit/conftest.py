# -*- coding: utf-8 -*-
"""Shared fixtures for the unit tests.

Keys are raw 32-byte Curve25519 secrets (no key files / passphrases needed):
the pack/unpack API accepts raw key bytes directly.
"""

import os
import pytest

from crypt4gh import sodium


@pytest.fixture
def keypair():
    """A (secret, public) Curve25519 keypair as raw bytes."""
    sk = os.urandom(32)
    pk = sodium.derive_pk(sk)
    return sk, pk


@pytest.fixture
def alice(keypair):
    sk, pk = keypair
    return {'sk': sk, 'pk': pk}


@pytest.fixture
def bob():
    sk = os.urandom(32)
    return {'sk': sk, 'pk': sodium.derive_pk(sk)}


@pytest.fixture
def sample_tree(tmp_path):
    """A small but representative source tree; returns its path."""
    root = tmp_path / 'src'
    (root / 'sub1' / 'deep').mkdir(parents=True)
    (root / 'sub2').mkdir()
    (root / 'empty').mkdir()
    (root / 'root.txt').write_text('file at root\n')
    (root / 'sub1' / 'a.txt').write_text('hello from sub1\n')
    (root / 'sub1' / 'deep' / 'rand.bin').write_bytes(os.urandom(5000))
    (root / 'sub2' / 'b.txt').write_text('hello from sub2\n')
    os.chmod(root / 'sub1' / 'a.txt', 0o640)
    os.symlink('../sub2/b.txt', root / 'sub1' / 'link_to_b')
    return root
