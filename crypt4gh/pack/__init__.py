# -*- coding: utf-8 -*-
"""Directory-aware packing/unpacking for Crypt4GH.

This subpackage adds the ``pack`` and ``unpack`` verbs: recursively encrypt a
source tree into a target tree (leaving the plaintext untouched), optionally
tarring each top-level subdirectory and compressing it before encryption, with
local or rsync-style remote (``[user@]host:/path``) endpoints.

The design keeps two concerns decoupled:

* **transform** -- walk the source, optionally tar + compress, then encrypt with
  the existing :mod:`crypt4gh.lib` streaming engine, staging the result in a
  local *working* directory alongside a SQLite catalog;
* **transport** -- move the staged files to/from a (possibly remote) endpoint.

That split is what a future Globus backend needs (it moves files at rest, not
pipes) and what keeps plaintext off the wire.
"""

from .api import pack, unpack

__all__ = ['pack', 'unpack']
