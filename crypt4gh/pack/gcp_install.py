# -*- coding: utf-8 -*-
"""Per-user installer for Globus Connect Personal (GCP) on Linux.

Automates https://docs.globus.org/globus-connect-personal/install/linux/ so a
transient Globus endpoint can be stood up without root: download the vendor
tarball (GCP is closed source and ~100 MB, so it is never vendored into the
repo), unpack it under ``~/.local/share/gcp/`` and drop a launcher symlink at
``~/.local/bin/globusconnectpersonal``.

Design notes
------------
* **Stdlib only.**  This may run as a bootstrap step *before* the project's
  virtualenv exists, so it must not import anything outside the standard
  library.
* **Idempotent.**  If ``globusconnectpersonal`` is already on ``PATH`` it is a
  no-op unless ``--force`` is given -- matching "install a copy only if we do
  not have one already".
* **Linux only.**  The tarball is Linux-specific; macOS and Windows have
  separate GCP builds.  The installer refuses to run elsewhere.
* **Integrity.**  Globus does not publish a checksum at a stable URL, so we
  always print the SHA-256 we downloaded and let ``--sha256`` pin it for
  repeatable installs.

Use as a library (the future ``globus`` transport backend calls
:func:`ensure_installed`) or as a CLI::

    python -m crypt4gh.pack.gcp_install            # install if missing
    python -m crypt4gh.pack.gcp_install --force    # reinstall
    crypt4gh-install-gcp --setup-key <KEY> --start # install, register, run

This installer only *installs* GCP.  Registering the endpoint still needs a
one-time setup key from https://app.globus.org/collections?add (there is no
fully headless registration without it); pass it with ``--setup-key`` or run
``globusconnectpersonal -setup`` yourself afterwards.
"""

import os
import sys
import time
import json
import stat
import shutil
import socket
import hashlib
import logging
import argparse
import platform
import tarfile
import tempfile
import subprocess
import urllib.request
from pathlib import Path

LOG = logging.getLogger(__name__)

#: Vendor download for the current stable Linux build.
DEFAULT_URL = (
    'https://downloads.globus.org/globus-connect-personal/linux/stable/'
    'globusconnectpersonal-latest.tgz'
)

#: Where the unpacked distribution and the launcher symlink live.
DEFAULT_SHARE_DIR = Path.home() / '.local' / 'share' / 'gcp'
DEFAULT_BIN_DIR = Path.home() / '.local' / 'bin'
LAUNCHER_NAME = 'globusconnectpersonal'

#: A dedicated Globus config directory for the endpoint we stand up, kept apart
#: from any pre-existing ``~/.globusonline`` so we never disturb an endpoint the
#: user already registered.  Passed to the launcher with ``-dir``.  ``None`` means
#: use the launcher's default (``~/.globusonline``).
DEFAULT_CONFIG_DIR = DEFAULT_SHARE_DIR / 'config'

_DOWNLOAD_CHUNK = 1 << 20  # 1 MiB


def _state_path():
    """Path of the per-user endpoint state file (XDG_CONFIG_HOME aware)."""
    base = os.environ.get('XDG_CONFIG_HOME') or (Path.home() / '.config')
    return Path(base) / 'crypt4gh' / 'globus.json'


def save_endpoint_state(endpoint_id, config_dir, *, restrict_paths=None, path=None):
    """Record ``{endpoint_id, config_dir, restrict_paths}`` so the transport can
    rediscover an isolated ``-dir`` endpoint that ``globus endpoint local-id``
    cannot see, and know which paths it currently shares.

    ``restrict_paths`` is the list of ``-restrict-paths`` rules the endpoint was
    last (re)started with -- the only record of an isolated endpoint's shared
    paths, which GCP keeps nowhere on disk.

    Best-effort: a write failure is logged, not raised -- a missing state file
    only costs us the auto-discovery convenience (the env override and the CLI
    remain).  Written atomically via a temp file + rename.
    """
    path = Path(path) if path else _state_path()
    data = {'endpoint_id': str(endpoint_id)}
    if config_dir is not None:
        data['config_dir'] = str(config_dir)
    if restrict_paths is not None:
        data['restrict_paths'] = list(restrict_paths)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + '.tmp')
        tmp.write_text(json.dumps(data, indent=2) + '\n')
        tmp.replace(path)
        LOG.info('Recorded local Globus endpoint in %s', path)
    except OSError as exc:
        LOG.warning('could not write endpoint state %s: %s', path, exc)


def load_endpoint_state(*, path=None):
    """Return the ``{endpoint_id, config_dir}`` dict, or ``None`` if unreadable.

    ``config_dir`` may be absent (a non-isolated endpoint).  Any IO or parse
    error -- including the file simply not existing -- yields ``None``.
    """
    path = Path(path) if path else _state_path()
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get('endpoint_id'):
        return None
    return data


#: The rule that keeps the user's home reachable; GCP's own default, which we
#: always preserve when we augment ``-restrict-paths`` with a working dir.
HOME_RULE = 'rw~/'


def restrict_rule_path(rule):
    """Split a ``-restrict-paths`` rule into ``(access, absolute_path)``.

    A rule is an optional access prefix (any of ``r``/``w``/``n``, case
    insensitive) followed by a path that may start with ``~``; no prefix means
    ``rw`` (GCP's default).  The path is ``~``-expanded and canonicalised so it
    can be prefix-matched against a real filesystem path.
    """
    i = 0
    while i < len(rule) and rule[i] in 'rwnRWN':
        i += 1
    access = rule[:i].lower() or 'rw'
    path = os.path.realpath(os.path.expanduser(rule[i:]))
    return access, path


def restrict_path_covered(path, rules):
    """True if ``path`` is granted (r or w) access by ``rules``.

    Uses longest-prefix-wins (matching GCP's own rule precedence), so a broad
    grant can be overridden by a more specific ``n`` (no access) rule.
    """
    target = os.path.realpath(path)
    best_len, best_access = -1, None
    for rule in rules:
        access, base = restrict_rule_path(rule)
        if target == base or target.startswith(base.rstrip(os.sep) + os.sep):
            if len(base) > best_len:
                best_len, best_access = len(base), access
    return best_access is not None and ('r' in best_access or 'w' in best_access)


def current_restrict_paths(*, state_path=None):
    """The endpoint's currently-shared rules, from the state file.

    Falls back to ``[HOME_RULE]`` (GCP's default) when we have not recorded a
    restart -- i.e. the endpoint is running with whatever it was last started
    with, which for a fresh :func:`ensure_usable` is home only.
    """
    state = load_endpoint_state(path=state_path)
    if state and state.get('restrict_paths'):
        return list(state['restrict_paths'])
    return [HOME_RULE]

#: How long to wait for a freshly started endpoint to report "connected".
_START_TIMEOUT = 60
_START_POLL = 3


class InstallError(RuntimeError):
    """A recoverable installation failure with a human-readable message."""


def find_on_path(name=LAUNCHER_NAME):
    """Return the path to an existing ``globusconnectpersonal`` on ``PATH``, or None."""
    found = shutil.which(name)
    return Path(found) if found else None


def _download(url, dest, *, expected_sha256=None):
    """Stream ``url`` to ``dest`` (a Path), returning the hex SHA-256.

    Verifies against ``expected_sha256`` when given.
    """
    LOG.info('Downloading %s', url)
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(url) as resp, open(dest, 'wb') as out:  # noqa: S310 (https URL)
            while True:
                chunk = resp.read(_DOWNLOAD_CHUNK)
                if not chunk:
                    break
                out.write(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise InstallError(f'download failed: {exc}') from exc

    got = digest.hexdigest()
    LOG.info('SHA-256 %s', got)
    if expected_sha256 and got.lower() != expected_sha256.lower():
        raise InstallError(
            f'checksum mismatch: expected {expected_sha256}, got {got}'
        )
    return got


def _safe_extract(tgz_path, into):
    """Extract ``tgz_path`` under ``into`` and return the top-level directory.

    Uses the tar ``data`` filter (Python 3.12+, always available on the 3.13+
    target) to reject absolute paths, traversal and unsafe members.
    """
    into.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(tgz_path, 'r:gz') as tar:
            members = tar.getmembers()
            tops = {Path(m.name).parts[0] for m in members if m.name not in ('', '.')}
            if len(tops) != 1 or tops & {'..', '/', os.sep}:
                raise InstallError(
                    f'unexpected archive layout: {sorted(tops) or "empty"}'
                )
            tar.extractall(into, filter='data')
    except tarfile.TarError as exc:
        raise InstallError(f'could not unpack archive: {exc}') from exc
    return into / tops.pop()


def _link_launcher(dist_dir, bin_dir):
    """Point ``bin_dir/globusconnectpersonal`` at the launcher in ``dist_dir``.

    The launcher resolves its own symlink to locate its bundled libraries, so a
    symlink (not a copy) is the supported way to expose it on ``PATH``.
    """
    target = dist_dir / LAUNCHER_NAME
    if not target.exists():
        raise InstallError(f'launcher not found in distribution: {target}')
    # The extracted launcher is not always +x in the tarball.
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    bin_dir.mkdir(parents=True, exist_ok=True)
    link = bin_dir / LAUNCHER_NAME
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target)
    return link


def ensure_installed(*, url=DEFAULT_URL, share_dir=DEFAULT_SHARE_DIR,
                     bin_dir=DEFAULT_BIN_DIR, force=False, expected_sha256=None):
    """Install Globus Connect Personal for the current user if it is missing.

    Returns the path to the usable ``globusconnectpersonal`` launcher.  If one
    is already on ``PATH`` and ``force`` is false, that path is returned and
    nothing is downloaded.
    """
    if platform.system() != 'Linux':
        raise InstallError(
            f'this installer is Linux-only (running on {platform.system()}); '
            'use the platform build from https://www.globus.org/globus-connect-personal'
        )

    if not force:
        existing = find_on_path()
        if existing:
            LOG.info('globusconnectpersonal already on PATH at %s', existing)
            return existing

    share_dir = Path(share_dir).expanduser()
    bin_dir = Path(bin_dir).expanduser()

    with tempfile.TemporaryDirectory(prefix='gcp-dl-') as tmp:
        tgz = Path(tmp) / 'globusconnectpersonal.tgz'
        sha = _download(url, tgz, expected_sha256=expected_sha256)
        dist_dir = _safe_extract(tgz, share_dir)

    launcher = _link_launcher(dist_dir, bin_dir)
    LOG.info('Installed %s -> %s', launcher, dist_dir)

    if not find_on_path():
        LOG.warning(
            '%s is not on your PATH; add it with: export PATH="%s:$PATH"',
            bin_dir, bin_dir,
        )
    LOG.info('Downloaded SHA-256: %s (pin with --sha256 for repeatable installs)', sha)
    return launcher


def _run_launcher(launcher, *args):
    """Run ``launcher`` with ``args``, raising :class:`InstallError` on failure."""
    cmd = [str(launcher), *args]
    LOG.info('Running: %s', ' '.join(cmd))
    try:
        subprocess.run(cmd, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(f'`{" ".join(cmd)}` failed: {exc}') from exc


# ----------------------------------------------------------------------
# make it *usable*: register (setup), start, and verify connectivity
# ----------------------------------------------------------------------
def _dir_args(config_dir):
    """The ``-dir`` argument list for a non-default config dir (else empty)."""
    return ['-dir', str(config_dir)] if config_dir else []


def _capture(launcher, *args, config_dir=None):
    """Run the launcher, capturing combined output; return (returncode, text)."""
    cmd = [str(launcher), *_dir_args(config_dir), *args]
    LOG.debug('running: %s', ' '.join(cmd))
    try:
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
    except OSError as exc:
        raise InstallError(f'`{" ".join(cmd)}` could not run: {exc}') from exc
    return proc.returncode, (proc.stdout or '')


def is_connected(launcher, *, config_dir=None):
    """True if a Globus Connect Personal instance is running *and* connected.

    ``globusconnectpersonal -status`` prints "connected" for a live endpoint and
    "No Globus Connect Personal connected to Globus Online Service" otherwise.
    """
    rc, out = _capture(launcher, '-status', config_dir=config_dir)
    low = out.lower()
    if 'no globus connect personal' in low or 'not connected' in low:
        return False
    return rc == 0 and 'connected' in low


def setup(launcher, setup_key, *, config_dir=None):
    """Register the endpoint with a one-time ``setup_key`` (idempotent-ish).

    A config dir that is already set up makes ``-setup`` refuse; the caller
    checks :func:`is_connected` first, so we pass ``-setup`` plainly here.
    """
    if not setup_key:
        raise InstallError('a setup key is required to register the endpoint')
    if config_dir:
        Path(config_dir).mkdir(parents=True, exist_ok=True)
    rc, out = _capture(launcher, '-setup', '--setup-key', setup_key, config_dir=config_dir)
    if rc != 0:
        raise InstallError(f'endpoint setup failed: {out.strip() or f"rc={rc}"}')
    LOG.info('Endpoint registered%s', f' in {config_dir}' if config_dir else '')


def start(launcher, *, config_dir=None, restrict_paths=None, timeout=_START_TIMEOUT,
          verify=None):
    """Start the endpoint in the background and wait until it is usable.

    ``restrict_paths`` is a list of rules passed as ``-restrict-paths``; it takes
    effect only at start time and overrides any GUI-configured paths, so this is
    how an isolated ``-dir`` endpoint's shared paths are set.

    ``verify`` is an optional zero-arg predicate for *true* reachability (e.g. a
    transfer-API round-trip): local ``-status`` can report ``connected`` while
    the Globus cloud still 502s for a few seconds, so when given, ``start`` polls
    ``verify`` until it returns true (or ``timeout`` elapses) before returning.
    """
    if is_connected(launcher, config_dir=config_dir):
        LOG.info('Endpoint already connected')
    else:
        log_path = Path(config_dir or DEFAULT_SHARE_DIR)
        log_path.mkdir(parents=True, exist_ok=True)
        logfile = log_path / 'gcp-start.log'
        cmd = [str(launcher), *_dir_args(config_dir), '-start']
        if restrict_paths:
            cmd += ['-restrict-paths', ','.join(restrict_paths)]
        LOG.info('Starting endpoint: %s (log: %s)', ' '.join(cmd), logfile)
        try:
            with open(logfile, 'ab') as lf:
                subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, start_new_session=True)
        except OSError as exc:
            raise InstallError(f'could not start endpoint: {exc}') from exc

        deadline = time.monotonic() + timeout
        while not is_connected(launcher, config_dir=config_dir):
            if time.monotonic() >= deadline:
                raise InstallError(
                    f'endpoint did not report "connected" within {timeout}s; '
                    f'see {logfile}')
            time.sleep(_START_POLL)
        LOG.info('Endpoint connected')

    if verify is not None:
        deadline = time.monotonic() + timeout
        while not verify():
            if time.monotonic() >= deadline:
                raise InstallError(
                    'endpoint reported connected but was not reachable via the '
                    f'Globus transfer API within {timeout}s (GCDisconnected lag)')
            time.sleep(_START_POLL)
        LOG.info('Endpoint reachable via the Globus transfer API')


def stop(launcher, *, config_dir=None):
    """Stop a running endpoint (no error if it was not running)."""
    _capture(launcher, '-stop', config_dir=config_dir)


def restart(launcher, *, config_dir=None, restrict_paths=None, timeout=_START_TIMEOUT,
            verify=None):
    """Stop then start the endpoint, applying ``restrict_paths``, and wait until
    it is reconnected (and, if ``verify`` is given, actually reachable).

    Restarting is the only way to change an endpoint's accessible paths: GCP
    reads ``-restrict-paths`` at start time (verified by the ih8.2 spike).
    """
    stop(launcher, config_dir=config_dir)
    start(launcher, config_dir=config_dir, restrict_paths=restrict_paths,
          timeout=timeout, verify=verify)


def ensure_path_shared(launcher, endpoint_id, config_dir, path, *, state_path=None,
                       verify=None):
    """Ensure ``path`` is reachable by the endpoint, restarting once if not.

    Idempotent: a no-op (returns ``False``) when ``path`` is already covered by
    the recorded rules.  Otherwise appends ``rw<realpath>`` to the current rules,
    restarts the endpoint with the augmented set (waiting on ``verify`` for true
    reachability), records it in the state file, and returns ``True``.
    """
    rules = current_restrict_paths(state_path=state_path)
    if restrict_path_covered(path, rules):
        LOG.info('%s is already shared by the local Globus endpoint', path)
        return False
    new_rules = rules + ['rw' + os.path.realpath(path)]
    LOG.info('Sharing %s with the local Globus endpoint (restart)', path)
    restart(launcher, config_dir=config_dir, restrict_paths=new_rules, verify=verify)
    save_endpoint_state(endpoint_id, config_dir, restrict_paths=new_rules, path=state_path)
    return True


def create_setup_key(name):
    """Create a GCP endpoint via the ``globus`` CLI and return (id, setup_key).

    Uses ``globus gcp create mapped`` (the successor to the removed
    ``globus endpoint create --personal``).  Requires an authenticated ``globus``
    CLI (``globus login``).  Kept isolated so the exact CLI surface is easy to
    adjust per Globus CLI version.
    """
    if shutil.which('globus') is None:
        raise InstallError(
            'the `globus` CLI is needed to auto-create a setup key; either run '
            '`globus login`, or pass --setup-key from '
            'https://app.globus.org/collections?add')
    argv = ['globus', 'gcp', 'create', 'mapped', name, '-F', 'json']
    try:
        out = subprocess.run(argv, check=True, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        detail = getattr(exc, 'stderr', '') or exc
        raise InstallError(f'`globus endpoint create` failed: {detail}') from exc
    try:
        doc = json.loads(out)
    except json.JSONDecodeError as exc:
        raise InstallError(f'could not parse `globus endpoint create` output: {exc}') from exc
    ep_id = doc.get('id') or doc.get('canonical_name')
    key = doc.get('globus_connect_setup_key') or doc.get('setup_key')
    if not ep_id or not key:
        raise InstallError(f'setup key/endpoint id missing from response: {doc}')
    return ep_id, key


def _client_id_file(config_dir):
    return Path(config_dir) / 'lta' / 'client-id.txt'


def endpoint_id_from_config(config_dir):
    """The endpoint id a registered ``-dir`` config records, or ``None``.

    GCP writes the endpoint's UUID to ``<config_dir>/lta/client-id.txt`` at
    registration (verified live on GCP 3.2.8), so an endpoint set up before the
    state file existed can still be identified from its config dir alone.
    """
    if not config_dir:
        return None
    try:
        return _client_id_file(config_dir).read_text().strip() or None
    except OSError:
        return None


def _record_endpoint(endpoint_id, config_dir, *, path=None):
    """Persist ``endpoint_id``/``config_dir`` to the state file, keeping the
    recorded ``restrict_paths`` when the file already describes this endpoint
    (re-running the installer must not forget what the transport has shared)."""
    state = load_endpoint_state(path=path)
    keep = None
    if state and state['endpoint_id'] == str(endpoint_id):
        keep = state.get('restrict_paths')
    save_endpoint_state(endpoint_id, config_dir, restrict_paths=keep, path=path)


def ensure_usable(*, name=None, setup_key=None, config_dir=DEFAULT_CONFIG_DIR,
                  url=DEFAULT_URL, share_dir=DEFAULT_SHARE_DIR, bin_dir=DEFAULT_BIN_DIR,
                  expected_sha256=None, force_install=False):
    """Install (if missing), register and start a *usable* GCP endpoint.

    Returns ``(launcher_path, endpoint_id_or_None)``.  If a connected endpoint
    already exists for ``config_dir`` nothing is started.  A fresh registration
    uses ``setup_key`` when given, else auto-creates one via the ``globus`` CLI.

    Whenever the endpoint id is known (a fresh auto-create, or read back from
    ``config_dir``) it is recorded in the state file with the config dir, so the
    transport can find this endpoint -- ``globus endpoint local-id`` cannot see
    an isolated ``-dir`` endpoint.  That includes an endpoint that was already
    registered or running, e.g. one set up before the state file existed.
    """
    launcher = ensure_installed(url=url, share_dir=share_dir, bin_dir=bin_dir,
                                force=force_install, expected_sha256=expected_sha256)

    ep_id = None
    if is_connected(launcher, config_dir=config_dir):
        LOG.info('A connected Globus Connect Personal endpoint is already running')
    else:
        already_setup = bool(config_dir) and _client_id_file(config_dir).exists()
        if not already_setup:
            if not setup_key:
                name = name or f'crypt4gh-{socket.gethostname()}'
                LOG.info('Auto-creating a Globus endpoint %r via the globus CLI', name)
                ep_id, setup_key = create_setup_key(name)
            setup(launcher, setup_key, config_dir=config_dir)
        start(launcher, config_dir=config_dir)

    ep_id = ep_id or endpoint_id_from_config(config_dir)
    if ep_id:
        _record_endpoint(ep_id, config_dir)
    return launcher, ep_id


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='crypt4gh-install-gcp',
        description='Install a per-user copy of Globus Connect Personal (Linux) '
                    'if one is not already on PATH.',
    )
    parser.add_argument('--url', default=DEFAULT_URL,
                        help='Tarball URL (default: current stable Linux build).')
    parser.add_argument('--share-dir', type=Path, default=DEFAULT_SHARE_DIR,
                        help='Where to unpack the distribution '
                             '(default: ~/.local/share/gcp).')
    parser.add_argument('--bin-dir', type=Path, default=DEFAULT_BIN_DIR,
                        help='Where to place the launcher symlink '
                             '(default: ~/.local/bin).')
    parser.add_argument('--sha256', metavar='HEX',
                        help='Expected SHA-256 of the tarball; abort on mismatch.')
    parser.add_argument('--force', action='store_true',
                        help='Reinstall even if globusconnectpersonal is on PATH.')
    parser.add_argument('--ensure-usable', action='store_true',
                        help='Install AND register AND start, then verify the endpoint '
                             'is connected -- the one-shot "give me a working endpoint" path. '
                             'Uses --setup-key if given, else auto-creates one via the '
                             'authenticated `globus` CLI. No-op if already connected.')
    parser.add_argument('--name', metavar='NAME',
                        help='Display name for an auto-created endpoint '
                             '(default: crypt4gh-<hostname>).')
    parser.add_argument('--dir', dest='config_dir', type=Path, default=None,
                        help='Globus config directory for this endpoint (passed as '
                             '-dir). Default with --ensure-usable is '
                             f'{DEFAULT_CONFIG_DIR}, kept apart from any existing '
                             '~/.globusonline. Pass "" to use the launcher default.')
    parser.add_argument('--setup-key', metavar='KEY',
                        help='Register the endpoint with this setup '
                             'key from https://app.globus.org/collections?add '
                             '(runs `globusconnectpersonal -setup --setup-key KEY`).')
    parser.add_argument('--start', action='store_true',
                        help='After install/setup, start the endpoint '
                             '(runs `globusconnectpersonal -start &`).')
    parser.add_argument('--stop', action='store_true',
                        help='Stop a running endpoint for --dir and exit.')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increase logging verbosity.')
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING - 10 * min(args.verbose, 2),
        format='%(message)s',
    )

    try:
        if args.stop:
            installed = Path(args.bin_dir) / LAUNCHER_NAME
            launcher = find_on_path() or (installed if installed.exists() else None)
            if not launcher:
                raise InstallError('no globusconnectpersonal found to stop')
            stop(launcher, config_dir=(args.config_dir or None))
            print('Stopped.', file=sys.stderr)
            return 0

        if args.ensure_usable:
            config_dir = DEFAULT_CONFIG_DIR if args.config_dir is None else (args.config_dir or None)
            launcher, ep_id = ensure_usable(
                name=args.name, setup_key=args.setup_key, config_dir=config_dir,
                url=args.url, share_dir=args.share_dir, bin_dir=args.bin_dir,
                expected_sha256=args.sha256, force_install=args.force,
            )
            print('Globus Connect Personal is installed, registered and connected.',
                  file=sys.stderr)
            if ep_id:
                print(f'  endpoint id: {ep_id} (recorded in {_state_path()})',
                      file=sys.stderr)
            if config_dir:
                print(f'  config dir : {config_dir} '
                      f'(manage with: {launcher} -dir {config_dir} -status|-stop)',
                      file=sys.stderr)
            return 0

        launcher = ensure_installed(
            url=args.url, share_dir=args.share_dir, bin_dir=args.bin_dir,
            force=args.force, expected_sha256=args.sha256,
        )
        if args.setup_key:
            _run_launcher(launcher, '-setup', '--setup-key', args.setup_key)
        if args.start:
            _run_launcher(launcher, '-start')
    except InstallError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

    if not (args.setup_key or args.start):
        print(
            'Installed the binary only. For a working endpoint in one step:\n'
            f'  {sys.argv[0] if sys.argv else "crypt4gh-install-gcp"} --ensure-usable\n'
            'or do it by hand:\n'
            '  1. Create a collection + setup key at '
            'https://app.globus.org/collections?add\n'
            f'  2. {launcher} -setup --setup-key <KEY>\n'
            f'  3. {launcher} -start &',
            file=sys.stderr,
        )
    return 0


if __name__ == '__main__':
    sys.exit(main())
