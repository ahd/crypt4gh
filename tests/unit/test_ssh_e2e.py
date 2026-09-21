# -*- coding: utf-8 -*-
"""End-to-end tests over a real ssh transport, using localhost as the "remote".

Skipped automatically unless passwordless ssh-to-localhost works (so they run in
CI / dev boxes with an sshd + key, and stay out of the way everywhere else).
These exercise the paths that have no in-process substitute: rsync-over-ssh
push/pull (`transport`) and ssh `find`/`cat`/`tar` streaming (`fs.RemoteFS`).
"""

import os
import subprocess

import pytest

from crypt4gh.pack import api
from treecmp import assert_trees_equal


def _ssh_localhost_ok():
    try:
        return subprocess.run(
            ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=4',
             '-o', 'StrictHostKeyChecking=accept-new', 'localhost', 'true'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(
    not _ssh_localhost_ok(),
    reason='passwordless ssh to localhost is not available',
)


def test_pack_to_remote_then_unpack_from_remote(sample_tree, tmp_path, alice, bob):
    """local source -> remote dest (rsync/ssh push); remote source -> local dest (pull)."""
    enc = tmp_path / 'enc'          # stands in as the remote directory
    dec = tmp_path / 'dec'
    api.pack(str(sample_tree), f'localhost:{enc}', seckey=bob['sk'],
             recipient_pubkeys=[alice['pk']], working_dir=str(tmp_path / 'w1'), jobs=1)
    assert (enc / 'catalog.sqlite').exists()   # was pushed to the "remote"

    api.unpack(f'localhost:{enc}', str(dec), seckey=alice['sk'],
               working_dir=str(tmp_path / 'w2'), jobs=1)
    assert_trees_equal(sample_tree, dec)


def test_pack_from_remote_source_mirror(sample_tree, tmp_path, alice, bob):
    """remote source streamed over ssh (find + cat), mirror mode, local dest."""
    enc, dec = tmp_path / 'enc', tmp_path / 'dec'
    api.pack(f'localhost:{sample_tree}', str(enc), seckey=bob['sk'],
             recipient_pubkeys=[alice['pk']], jobs=1)
    api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=1)
    assert_trees_equal(sample_tree, dec)


def test_pack_from_remote_source_tar_gzip(sample_tree, tmp_path, alice, bob):
    """remote source streamed over ssh (find + tar) with compression."""
    enc, dec = tmp_path / 'enc', tmp_path / 'dec'
    api.pack(f'localhost:{sample_tree}', str(enc), seckey=bob['sk'],
             recipient_pubkeys=[alice['pk']], tar=True, compress='gzip', jobs=1)
    api.unpack(str(enc), str(dec), seckey=alice['sk'], jobs=1)
    assert_trees_equal(sample_tree, dec)
