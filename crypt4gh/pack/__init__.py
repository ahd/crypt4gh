# -*- coding: utf-8 -*-
"""Directory-aware packing/unpacking for Crypt4GH.

This subpackage adds the ``pack`` and ``unpack`` verbs: recursively encrypt a
source tree into a target tree (leaving the plaintext untouched), optionally
tarring each top-level subdirectory and compressing it before encryption, with
local, rsync-style remote (``[user@]host:/path``) or Globus
(``globus:<collection-id>:/path``) endpoints.

The design keeps two concerns decoupled:

* **transform** -- walk the source, optionally tar + compress, then encrypt with
  the existing :mod:`crypt4gh.lib` streaming engine, staging the result in a
  local *working* directory alongside a SQLite catalog;
* **transport** -- move the staged files to/from a (possibly remote) endpoint.

That split is what the Globus backend needs (it moves files at rest, not
pipes) and what keeps plaintext off the wire.  The Globus side lives in
:mod:`.globus` (the ``globus`` CLI wrappers), :mod:`.gcp_install` (install and
manage the local Globus Connect Personal endpoint) and
:func:`.transport.ensure_endpoint` (make it ready before each transfer);
logging for a run is set up by :mod:`.logsetup`.
"""

from .api import pack, unpack

__all__ = ['pack', 'unpack']
