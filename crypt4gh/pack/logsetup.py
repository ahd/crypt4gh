# -*- coding: utf-8 -*-
"""Logging setup for ``pack``/``unpack``, shared with their worker processes.

Two destinations, configured independently:

* **the terminal** (stderr), quiet by default and raised by ``-v``/``-vv`` or
  ``C4GH_DEBUG`` -- unchanged from before ``--log`` existed;
* **``--log FILE``** (default ``$C4GH_LOG``), as for the streaming verbs:

  - if FILE exists and holds a JSON :func:`logging.config.dictConfig`
    document, that configuration is applied as-is (the same contract as
    ``crypt4gh --log``);
  - otherwise FILE is a log file that records are *appended* to, at INFO
    (DEBUG with ``-vv``/``C4GH_DEBUG``) whatever the terminal shows, with
    timestamps and process names so parallel workers can be told apart.

The per-item transform runs in a process pool; on Python 3.14+ its workers
start via *forkserver*, so they inherit no logging configuration from the
parent.  :func:`worker_init` (a pool initializer) re-applies the parent's
configuration from :func:`current`, so worker warnings and errors reach the
same destinations.
"""

import os
import sys
import json
import logging
from logging.config import dictConfig

TERMINAL_FORMAT = '[%(levelname)s] %(message)s'
FILE_FORMAT = '%(asctime)s %(processName)s [%(levelname)s] %(name)s: %(message)s'

#: Mark a record already shown to the user on the terminal (e.g. a CLI error
#: that is also printed) so it goes to the log file only: ``extra=QUIET``.
QUIET = {'terminal': False}

_current = None


def _terminal_level(verbose):
    if os.getenv('C4GH_DEBUG') or verbose >= 2:
        return logging.DEBUG
    if verbose == 1:
        return logging.INFO
    return logging.CRITICAL


def _load_dict_config(path):
    """The dictConfig document in ``path``, or ``None`` if it is not one."""
    try:
        with open(path, 'rt') as stream:
            doc = json.load(stream)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and 'version' in doc else None


def configure(verbose=0, log=None):
    """Configure the root logger for a pack/unpack run (idempotent).

    Returns the log file path records are appended to, or ``None`` (no
    ``--log``, or ``--log`` named a dictConfig document).
    """
    global _current
    _current = (verbose, log)

    terminal = logging.StreamHandler(sys.stderr)
    terminal.setLevel(_terminal_level(verbose))
    terminal.setFormatter(logging.Formatter(TERMINAL_FORMAT))
    terminal.addFilter(lambda record: getattr(record, 'terminal', True))
    handlers = [terminal]

    logfile = None
    config = None
    if log:
        log = os.path.expanduser(log)
        config = _load_dict_config(log)
        if config is None:
            logfile = log
            fh = logging.FileHandler(logfile, mode='a', encoding='utf-8')
            fh.setLevel(logging.DEBUG if _terminal_level(verbose) == logging.DEBUG
                        else logging.INFO)
            fh.setFormatter(logging.Formatter(FILE_FORMAT))
            handlers.append(fh)

    root = logging.getLogger()
    # Replace our own handlers, never stack them (re-entry, or a forked worker
    # inheriting the parent's); leave anyone else's alone.
    for h in [h for h in root.handlers if getattr(h, '_c4gh', False)]:
        root.removeHandler(h)
        h.close()
    for h in handlers:
        h._c4gh = True
        root.addHandler(h)
    root.setLevel(min(h.level for h in handlers))

    if config is not None:
        dictConfig(config)
    return logfile


def current():
    """The ``(verbose, log)`` the parent configured, for :func:`worker_init`."""
    return _current


def worker_init(config):
    """Process-pool initializer: re-apply the parent's logging configuration."""
    if config is not None:
        configure(*config)
