# -*- coding: utf-8 -*-
"""Helper to assert two directory trees are equivalent."""

import os
import stat


def _entries(root):
    """Map relpath -> (kind, payload) for every file/dir/symlink under root."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                out[rel] = ('symlink', os.readlink(full))
                dirnames.remove(name)
            else:
                out[rel] = ('dir', None)
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                out[rel] = ('symlink', os.readlink(full))
            else:
                with open(full, 'rb') as f:
                    out[rel] = ('file', f.read())
    return out


def assert_trees_equal(a, b, check_mode=True):
    ea, eb = _entries(a), _entries(b)
    assert set(ea) == set(eb), f'tree membership differs: {set(ea) ^ set(eb)}'
    for rel, (kind, payload) in ea.items():
        assert eb[rel][0] == kind, f'{rel}: kind {eb[rel][0]} != {kind}'
        assert eb[rel][1] == payload, f'{rel}: content/target differs'
        if check_mode and kind != 'symlink':
            ma = stat.S_IMODE(os.lstat(os.path.join(a, rel)).st_mode)
            mb = stat.S_IMODE(os.lstat(os.path.join(b, rel)).st_mode)
            assert ma == mb, f'{rel}: mode {oct(mb)} != {oct(ma)}'
