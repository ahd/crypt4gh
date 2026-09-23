# -*- coding: utf-8 -*-
"""Endpoint parsing and at-rest transfer (local move / rsync-over-ssh).

An endpoint is a local path, an rsync-style ``[user@]host:/path`` (ssh), or a
``globus:<endpoint-id>:/path`` Globus collection.  The staged working directory
is materialised locally first; this module then moves it to (or pulls it from)
the endpoint.  The "stage the lot, then push" model is exactly what Globus needs,
since GridFTP transfers files at rest between endpoints -- the local side is this
host's Globus Connect Personal endpoint (see :mod:`crypt4gh.pack.globus`).
"""

import os
import re
import shutil
import shlex
import logging
import subprocess
from dataclasses import dataclass

LOG = logging.getLogger(__name__)

# [user@]host:path  -- host has no slash and there is a colon before any slash.
_REMOTE_RE = re.compile(r'^(?:(?P<user>[^@/]+)@)?(?P<host>[^@/:]+):(?P<path>.*)$')

# globus:<endpoint-id>:/collection/path
_GLOBUS_PREFIX = 'globus:'


@dataclass
class Endpoint:
    kind: str          # 'local' | 'ssh' | 'globus'
    path: str
    host: str = None   # ssh hostname, or globus endpoint/collection id
    user: str = None

    @property
    def is_remote(self):
        return self.kind != 'local'

    def __str__(self):
        if self.kind == 'ssh':
            host = f'{self.user}@{self.host}' if self.user else self.host
            return f'{host}:{self.path}'
        if self.kind == 'globus':
            return f'globus:{self.host}:{self.path}'
        return self.path


def parse_endpoint(spec):
    """Parse a source/dest spec into an :class:`Endpoint`.

    * ``globus:<endpoint-id>:/path`` is a Globus collection (checked first, so
      the ssh regex does not mistake the ``globus`` prefix for a hostname).
    * ``[user@]host:path`` is remote (ssh).
    * anything else is a local path.  A bare Windows-style drive letter is not
      a concern on the Linux target.
    """
    if spec.startswith(_GLOBUS_PREFIX):
        ep_id, sep, path = spec[len(_GLOBUS_PREFIX):].partition(':')
        if not sep or not ep_id:
            raise ValueError(
                "Globus endpoint must be 'globus:<endpoint-id>:/path' "
                f'(got {spec!r})')
        return Endpoint(kind='globus', host=ep_id, path=path or '/')
    m = _REMOTE_RE.match(spec)
    if m:
        return Endpoint(kind='ssh', host=m.group('host'), user=m.group('user'),
                        path=m.group('path') or '.')
    return Endpoint(kind='local', path=os.path.abspath(os.path.expanduser(spec)))


def _hostspec(ep):
    return f'{ep.user}@{ep.host}' if ep.user else ep.host


def _rsync(src, dst):
    # NB: no --mkpath (needs rsync 3.2.3+; macOS ships 2.6.9). The destination
    # directory is created explicitly before rsync runs.
    argv = ['rsync', '-a', '--partial', src, dst]
    LOG.info('rsync %s -> %s', src, dst)
    subprocess.check_call(argv)


def _ssh_mkdir(dest):
    subprocess.check_call(['ssh', _hostspec(dest), f'mkdir -p {shlex.quote(dest.path)}'])


#: Opt into auto-installing a brand-new endpoint when none is configured.
GLOBUS_AUTO_INSTALL_ENV = 'C4GH_GLOBUS_AUTO_INSTALL'


def _env_flag(name):
    return os.getenv(name, '').strip().lower() in ('1', 'true', 'yes', 'on')


def ensure_endpoint(working_dir, *, auto_install=None, endpoint_id=None,
                    config_dir=None, name=None):
    """Make the local Globus endpoint ready to transfer ``working_dir``.

    Orchestrates, in order:

    * **resolve** the local endpoint id + config dir (explicit args win, else
      env override / state file / ``globus endpoint local-id``);
    * **C** -- if nothing resolved: install+register a fresh endpoint, but only
      when ``auto_install`` is set (defaults to the
      :data:`GLOBUS_AUTO_INSTALL_ENV` env flag); otherwise raise a clear error;
    * **A** -- ensure ``working_dir`` is shared (restarts once if not), and
    * **B** -- start the endpoint if it is not already connected.

    :returns: the resolved endpoint id (to address the local side of the
        transfer).
    """
    from . import globus, gcp_install
    if auto_install is None:
        auto_install = _env_flag(GLOBUS_AUTO_INSTALL_ENV)

    if endpoint_id is None:
        try:
            endpoint_id, resolved_cfg = globus.resolve_local_endpoint()
        except globus.GlobusError:
            endpoint_id, resolved_cfg = None, None
        if config_dir is None:
            config_dir = resolved_cfg

    if not endpoint_id:
        if not auto_install:
            raise globus.GlobusError(
                'no local Globus endpoint is configured. Run '
                '`crypt4gh-install-gcp --ensure-usable` once, set '
                f'{globus.LOCAL_ENDPOINT_ENV}=<endpoint-id>, or enable '
                f'auto-install ({GLOBUS_AUTO_INSTALL_ENV}=1 / --install-gcp).')
        if config_dir is None:
            config_dir = str(gcp_install.DEFAULT_CONFIG_DIR)
        LOG.info('No local Globus endpoint configured; auto-installing one')
        _launcher, endpoint_id = gcp_install.ensure_usable(name=name, config_dir=config_dir)
        if not endpoint_id:  # a pre-existing connected endpoint: re-resolve its id
            endpoint_id, cfg2 = globus.resolve_local_endpoint()
            config_dir = config_dir or cfg2

    launcher = gcp_install.find_on_path()
    if launcher is None:
        # A managed collection / DTN we do not run locally: cannot manage its
        # lifecycle, so only warn if we can tell the dir is not reachable.
        ok, reason = globus.working_is_shared(working_dir)
        if not ok:
            LOG.warning('%s', reason)
        return endpoint_id

    # Wait for a real transfer-API round-trip, not just local -status, after any
    # (re)start: a freshly started endpoint can 502 (GCDisconnected) for seconds.
    verify = lambda: globus.endpoint_reachable(endpoint_id)  # noqa: E731

    # A: share the working dir (restarts, so also brings a stopped endpoint up).
    if not gcp_install.ensure_path_shared(launcher, endpoint_id, config_dir,
                                          working_dir, verify=verify):
        # Already shared -- B: just make sure it is running (and reachable).
        gcp_install.start(launcher, config_dir=config_dir,
                          restrict_paths=gcp_install.current_restrict_paths(),
                          verify=verify)
    return endpoint_id


def _globus_local_spec(endpoint_id, working_dir):
    """Address the local staging dir as ``<endpoint-id>:<realpath>``.

    Realpath (not just abspath) because GCP canonicalises the addressed path
    before applying its ``-restrict-paths`` rules (ih8.2 spike)."""
    return f'{endpoint_id}:{os.path.realpath(working_dir)}'


def push(working_dir, dest, *, globus=None):
    """Move/copy the staged ciphertext (or plaintext) tree to the destination.

    ``globus`` is an optional dict of endpoint-management options (endpoint_id,
    config_dir, name, auto_install) forwarded to :func:`ensure_endpoint` on a
    globus leg; ignored for local/ssh destinations.
    """
    src = os.path.join(working_dir, '')  # trailing slash: copy contents
    if dest.kind == 'local':
        os.makedirs(dest.path, exist_ok=True)
        _rsync(src, os.path.join(dest.path, ''))
    elif dest.kind == 'ssh':
        _ssh_mkdir(dest)
        _rsync(src, f'{_hostspec(dest)}:{dest.path}/')
    elif dest.kind == 'globus':
        from . import globus as globus_mod
        endpoint_id = ensure_endpoint(working_dir, **(globus or {}))
        local = _globus_local_spec(endpoint_id, working_dir)
        globus_mod.transfer(local, f'{dest.host}:{dest.path}', label='crypt4gh pack')
    else:
        raise ValueError(f'Unsupported destination kind: {dest.kind}')


def pull(source, working_dir, *, globus=None):
    """Fetch an at-rest tree (e.g. ciphertext for unpack) into the working dir.

    ``globus`` is forwarded to :func:`ensure_endpoint` on a globus leg (see
    :func:`push`); ignored for local/ssh sources.
    """
    os.makedirs(working_dir, exist_ok=True)
    dst = os.path.join(working_dir, '')
    if source.kind == 'local':
        _rsync(os.path.join(source.path, ''), dst)
    elif source.kind == 'ssh':
        _rsync(f'{_hostspec(source)}:{source.path}/', dst)
    elif source.kind == 'globus':
        from . import globus as globus_mod
        endpoint_id = ensure_endpoint(working_dir, **(globus or {}))
        local = _globus_local_spec(endpoint_id, working_dir)
        globus_mod.transfer(f'{source.host}:{source.path}', local, label='crypt4gh unpack')
    else:
        raise ValueError(f'Unsupported source kind: {source.kind}')
