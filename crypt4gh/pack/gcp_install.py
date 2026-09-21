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
import stat
import shutil
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

_DOWNLOAD_CHUNK = 1 << 20  # 1 MiB


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
    parser.add_argument('--setup-key', metavar='KEY',
                        help='After install, register the endpoint with this setup '
                             'key from https://app.globus.org/collections?add '
                             '(runs `globusconnectpersonal -setup --setup-key KEY`).')
    parser.add_argument('--start', action='store_true',
                        help='After install/setup, start the endpoint '
                             '(runs `globusconnectpersonal -start &`).')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increase logging verbosity.')
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING - 10 * min(args.verbose, 2),
        format='%(message)s',
    )

    try:
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

    if not args.setup_key:
        print(
            'Installed. Next, register the endpoint (one-time):\n'
            '  1. Create a collection + setup key at '
            'https://app.globus.org/collections?add\n'
            f'  2. {launcher} -setup --setup-key <KEY>\n'
            f'  3. {launcher} -start &',
            file=sys.stderr,
        )
    return 0


if __name__ == '__main__':
    sys.exit(main())
