# -*- coding: utf-8 -*-
"""Thin wrappers around the ``globus`` command-line client.

The pack/unpack transport shells out to the Globus CLI rather than embedding
``globus-sdk`` -- the CLI is already installed and authenticated on the target
data-mover hosts, it discovers the local Globus Connect Personal endpoint for
us (``globus endpoint local-id``), and shelling out matches how the rest of the
transport layer drives ``rsync``/``ssh``.  Every subprocess call goes through
:func:`_run`/:func:`_json` so unit tests can mock the CLI without a live Globus.

A GridFTP transfer needs a data-transfer server at *both* ends.  The remote end
is the target collection (``globus:<id>:/path``); the local end is this host's
GCP endpoint, whose id we look up here.  For that to move bytes at speed, the
staged ``--working`` directory must sit on storage the local endpoint exposes
(see :func:`working_is_shared`).
"""

import os
import json
import shutil
import logging
import subprocess

LOG = logging.getLogger(__name__)

GLOBUS_BIN = 'globus'

#: Override the auto-discovered local endpoint (e.g. on a host where
#: ``globus endpoint local-id`` is ambiguous or unset).
LOCAL_ENDPOINT_ENV = 'C4GH_GLOBUS_LOCAL_ENDPOINT'

#: Globus Connect Personal records its shared paths here.
CONFIG_PATHS = os.path.expanduser('~/.globusonline/lta/config-paths')


class GlobusError(RuntimeError):
    """A Globus CLI invocation failed (with a human-readable message)."""


def ensure_cli():
    """Raise :class:`GlobusError` if the ``globus`` CLI is not on PATH."""
    if shutil.which(GLOBUS_BIN) is None:
        raise GlobusError(
            f'the {GLOBUS_BIN!r} command was not found on PATH; install the '
            'Globus CLI (https://docs.globus.org/cli/) and run `globus login`')


def _run(args, **kw):
    """Run ``globus <args>``; raise :class:`GlobusError` on failure."""
    ensure_cli()
    argv = [GLOBUS_BIN, *args]
    LOG.debug('running: %s', ' '.join(argv))
    try:
        return subprocess.run(argv, check=True, text=True,
                              stdout=subprocess.PIPE, **kw)
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or '').strip()
        raise GlobusError(f'`globus {" ".join(args)}` failed: {detail or e}') from e


def _json(args):
    """Run ``globus <args> -F json`` and return the parsed document."""
    out = _run([*args, '-F', 'json']).stdout
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise GlobusError(f'could not parse `globus {" ".join(args)}` output: {e}') from e


def local_endpoint_id():
    """Return the id of this host's local (GCP) Globus endpoint.

    Honours the :data:`LOCAL_ENDPOINT_ENV` override, else asks the CLI.
    """
    override = os.getenv(LOCAL_ENDPOINT_ENV)
    if override:
        return override.strip()
    out = _run(['endpoint', 'local-id']).stdout.strip()
    if not out:
        raise GlobusError(
            'no local Globus endpoint found; start Globus Connect Personal, or '
            f'set {LOCAL_ENDPOINT_ENV} to the endpoint id')
    return out


def submit_transfer(src, dst, *, recursive=True, sync_level='checksum', label=None):
    """Submit a transfer ``src`` -> ``dst`` and return its task id.

    ``src``/``dst`` are ``<endpoint-id>:<path>`` strings.
    """
    args = ['transfer', src, dst]
    if recursive:
        args.append('--recursive')
    if sync_level:
        args += ['--sync-level', sync_level]
    if label:
        args += ['--label', label]
    doc = _json(args)
    task_id = doc.get('task_id')
    if not task_id:
        raise GlobusError(f'transfer submitted but no task id was returned: {doc}')
    LOG.info('Globus task %s submitted (%s -> %s)', task_id, src, dst)
    return task_id


def wait(task_id, *, polling_interval=15, timeout=None):
    """Block until a Globus task finishes; raise if it fails or times out."""
    args = ['task', 'wait', task_id, '--polling-interval', str(polling_interval)]
    if timeout:
        args += ['--timeout', str(timeout)]
    LOG.info('Waiting for Globus task %s', task_id)
    _run(args)


def transfer(src, dst, *, label=None, polling_interval=15, timeout=None):
    """Submit a recursive checksum-synced transfer and wait for completion."""
    task_id = submit_transfer(src, dst, label=label)
    wait(task_id, polling_interval=polling_interval, timeout=timeout)
    return task_id


def _shared_paths(config_paths=CONFIG_PATHS):
    """Parse Globus Connect Personal's ``config-paths`` into absolute prefixes.

    Each line is ``<path>,<sharing>,<rw>``; ``<path>`` may be ``~``-relative.
    Returns ``None`` when the file is absent (i.e. we cannot tell -- likely not
    a GCP host), so callers can distinguish "not shared" from "unknown".
    """
    if not os.path.exists(config_paths):
        return None
    prefixes = []
    with open(config_paths) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            path = line.split(',', 1)[0]
            prefixes.append(os.path.abspath(os.path.expanduser(path)))
    return prefixes


def working_is_shared(working_dir, config_paths=CONFIG_PATHS):
    """Best-effort check that ``working_dir`` sits on GCP-exposed storage.

    :returns: ``(ok, reason)``.  ``ok`` is False only on a *definite* miss; when
        we cannot tell (no config-paths file) it is True with ``reason=None`` so
        callers do not cry wolf on non-GCP hosts.
    """
    prefixes = _shared_paths(config_paths)
    if prefixes is None:
        return True, None
    wd = os.path.abspath(working_dir)
    for base in prefixes:
        if base == os.sep or wd == base or wd.startswith(base.rstrip(os.sep) + os.sep):
            return True, None
    return False, (f'{wd} is not under any path shared by the local Globus '
                   f'endpoint ({", ".join(prefixes) or "none"}); GridFTP cannot '
                   'reach it. Add it to ~/.globusonline/lta/config-paths.')
