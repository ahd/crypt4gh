# -*- coding: utf-8 -*-
"""Thin wrappers around the ``globus`` command-line client.

The pack/unpack transport shells out to the Globus CLI rather than embedding
``globus-sdk`` -- the CLI is already installed and authenticated on the target
data-mover hosts, and shelling out matches how the rest of the transport layer
drives ``rsync``/``ssh``.  The local Globus Connect Personal endpoint is found by
:func:`resolve_local_endpoint` (env override, then the state file, then
``globus endpoint local-id``).  Every subprocess call goes through
:func:`_run`/:func:`_json` so unit tests can mock the CLI without a live Globus.

A GridFTP transfer needs a data-transfer server at *both* ends.  The remote end
is the target collection (``globus:<id>:/path``); the local end is this host's
GCP endpoint, whose id we look up here.  For that to move bytes at speed, the
staged ``--working`` directory must sit on storage the local endpoint exposes;
:func:`crypt4gh.pack.transport.ensure_endpoint` shares it (restarting the
endpoint) and waits for :func:`endpoint_reachable` before transferring.
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


class GlobusError(RuntimeError):
    """A Globus CLI invocation failed (with a human-readable message)."""


def ensure_cli():
    """Raise :class:`GlobusError` if the ``globus`` CLI is not on PATH."""
    if shutil.which(GLOBUS_BIN) is None:
        raise GlobusError(
            f'the {GLOBUS_BIN!r} command was not found on PATH; install the '
            'Globus CLI (https://docs.globus.org/cli/) and run `globus login`')


def _run(args, **kw):
    """Run ``globus <args>``; raise :class:`GlobusError` on failure.

    stderr is captured (not passed through to the terminal) so an expected
    failure -- e.g. a reachability probe polling a starting endpoint -- stays
    quiet; its text is carried in the :class:`GlobusError` message instead.
    """
    ensure_cli()
    argv = [GLOBUS_BIN, *args]
    LOG.debug('running: %s', ' '.join(argv))
    kw.setdefault('stderr', subprocess.PIPE)
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


def resolve_local_endpoint():
    """Resolve this host's local (GCP) endpoint to ``(endpoint_id, config_dir)``.

    Resolution order:

    1. the :data:`LOCAL_ENDPOINT_ENV` override -> ``(id, None)``;
    2. the state file written by :func:`gcp_install.save_endpoint_state`
       (``~/.config/crypt4gh/globus.json``) -> ``(id, config_dir)`` -- the only
       way to find an *isolated* ``-dir`` endpoint, which the CLI below cannot
       see;
    3. ``globus endpoint local-id`` -> ``(id, None)``.

    ``config_dir`` is ``None`` for every source but the state file; callers that
    must ``-stop``/``-start`` the endpoint need that path, so an isolated
    endpoint has to come from the state file (or the env override plus a known
    dir) rather than the CLI.
    """
    override = os.getenv(LOCAL_ENDPOINT_ENV)
    if override:
        return override.strip(), None
    from . import gcp_install
    state = gcp_install.load_endpoint_state()
    if state:
        return state['endpoint_id'], state.get('config_dir')
    out = _run(['endpoint', 'local-id']).stdout.strip()
    if not out:
        raise GlobusError(
            'no local Globus endpoint found; start Globus Connect Personal, '
            f'run `crypt4gh-install-gcp --ensure-usable`, or set '
            f'{LOCAL_ENDPOINT_ENV} to the endpoint id')
    return out, None


def local_endpoint_id():
    """Return just the id of this host's local endpoint (see
    :func:`resolve_local_endpoint`)."""
    return resolve_local_endpoint()[0]


def endpoint_reachable(endpoint_id):
    """True if ``endpoint_id`` answers a transfer-API round-trip right now.

    A freshly (re)started Globus Connect Personal endpoint can report
    ``connected`` locally while the Globus cloud still returns 502
    ``GCDisconnected`` for a few seconds (ih8.2 spike, Q4).  A real ``globus ls``
    on the endpoint root is the authoritative signal, so callers can poll this
    after a start/restart before issuing a transfer.
    """
    try:
        _run(['ls', f'{endpoint_id}:/'])
        return True
    except GlobusError as e:
        LOG.debug('endpoint %s not reachable yet: %s', endpoint_id, e)
        return False


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
    # `task wait` returns once the task is *terminal*, failed or not; check.
    doc = _json(['task', 'show', task_id])
    status = doc.get('status')
    if status != 'SUCCEEDED':
        raise GlobusError(f'Globus task {task_id} ended {status or "in an unknown state"}: '
                          f'{doc.get("nice_status_short_description") or doc.get("nice_status") or ""}'
                          .rstrip(': '))
    LOG.info('Globus task %s succeeded (%s files, %s bytes)', task_id,
             doc.get('files_transferred'), doc.get('bytes_transferred'))


def transfer(src, dst, *, label=None, polling_interval=15, timeout=None):
    """Submit a recursive checksum-synced transfer and wait for completion."""
    task_id = submit_transfer(src, dst, label=label)
    wait(task_id, polling_interval=polling_interval, timeout=timeout)
    return task_id


def working_is_shared(working_dir, *, rules=None):
    """Best-effort check that ``working_dir`` sits on endpoint-exposed storage.

    An isolated ``-dir`` endpoint keeps its shared paths in no on-disk file;
    they are the ``-restrict-paths`` rules it was last started with, which we
    record in the state file.  ``rules`` overrides that lookup (used in tests
    and by the transport once it has resolved the endpoint).

    :returns: ``(ok, reason)``.  ``ok`` is False only on a *definite* miss; when
        we have no recorded rules (not our managed endpoint) it is True with
        ``reason=None`` so callers do not cry wolf on non-GCP hosts.
    """
    from . import gcp_install
    if rules is None:
        state = gcp_install.load_endpoint_state()
        if not state or not state.get('restrict_paths'):
            return True, None
        rules = state['restrict_paths']
    if gcp_install.restrict_path_covered(working_dir, rules):
        return True, None
    return False, (f'{os.path.realpath(working_dir)} is not under any path shared '
                   f'by the local Globus endpoint ({", ".join(rules) or "none"}); '
                   'GridFTP cannot reach it. Share it via endpoint '
                   'auto-management or restart with -restrict-paths.')
