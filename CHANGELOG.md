# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Directory-aware `pack` / `unpack` verbs** (`crypt4gh pack`, `crypt4gh unpack`).
  Recursively encrypt a source tree into a target tree (leaving the source
  plaintext untouched) and decrypt it back:
  - `--tar` packs each top-level subdirectory into one tar archive before
    encryption; loose files at the root are handled individually.
  - `--compress none|gzip|bzip2|zstd` (with optional level, e.g. `zstd:19`)
    compresses tarred subdirectories between tarring and encryption. `none` is
    the default.
  - rsync-style remote endpoints (`[user@]host:/path`) for either the source or
    the destination. Ciphertext is staged in a local `--working` directory and
    then moved with rsync-over-ssh; a remote *source* is streamed over ssh so
    plaintext is never staged at rest.
  - a SQLite catalog (`<working>/catalog.sqlite`) recording each item's size,
    mtime, mode, plaintext/ciphertext SHA-256 and processing state — the basis
    for integrity verification and a future `--resume`.
  - permissions, mtimes, empty directories and symlinks are preserved.
- Pluggable crypto and transport layers, so an encrypt-at-source mode and a
  Globus transport backend can be added without changing the pipeline.
- **Globus transport** (`globus:<endpoint-id>:/path`) for either the source or
  destination of `pack`/`unpack`. Ciphertext is staged locally, then moved at
  rest with GridFTP by shelling out to the `globus` CLI (`globus transfer` +
  `globus task wait`).
- **Self-managing local endpoint.** Before a `globus:` transfer, crypt4gh
  resolves this host's Globus Connect Personal endpoint
  (`C4GH_GLOBUS_LOCAL_ENDPOINT` → state file `~/.config/crypt4gh/globus.json` →
  `globus endpoint local-id`), starts it if it is not connected, and shares the
  working directory via GCP `-restrict-paths` (restarting once if needed) so
  GridFTP can reach the staged bytes. After any (re)start it waits for a real
  transfer-API round-trip — not just local `-status`, which can report
  `connected` while the Globus cloud still 502s (`GCDisconnected`) for a few
  seconds — before issuing the transfer. Installing a brand-new endpoint on the fly
  is opt-in (`C4GH_GLOBUS_AUTO_INSTALL=1` or `--install-gcp`); otherwise a
  missing endpoint is a clear error pointing at
  `crypt4gh-install-gcp --ensure-usable`. `pack`/`unpack` also accept
  `--globus-endpoint`, `--globus-config-dir` and `--globus-endpoint-name` to pin
  or name the local endpoint.
- **`crypt4gh-install-gcp`** (`crypt4gh.pack.gcp_install`): a Linux-only,
  stdlib-only per-user installer for Globus Connect Personal. Downloads the
  closed-source vendor tarball (not vendored into the repo) to
  `~/.local/share/gcp/` and links the launcher at
  `~/.local/bin/globusconnectpersonal`; a no-op when one is already on `PATH`.
  Verifies the download against an optional pinned `--sha256`, rejects unsafe
  archives, and can register (`--setup-key`) and start (`--start`) the endpoint.
  `--ensure-usable` does the lot in one shot (install, register, start, verify
  connected) and records the endpoint in the state file for the transport.
- A `pytest` unit-test suite under `tests/unit/` (crypto/header, key formats,
  KDFs, naming, codecs, catalog, transport parsing, and pack/unpack round-trips).

### Changed
- Packaging modernized: metadata moved to `pyproject.toml` (PEP 621); `setup.py`
  retained only as the libsodium C-extension build shim. `uv` is supported
  (`uv sync`, `uv run pytest`, `uv build`).
- Minimum Python raised to **3.13**.

### Fixed
- `crypt4gh.header.validate_edit_list` no longer raises `NameError` on the
  between-reads skip check and no longer `IndexError`s on an empty edit list.
  (The function was previously unreachable; it is now correct and unit-tested.)
- `unpack` no longer mutates the source ciphertext directory: the catalog is
  opened read-only + immutable, so decrypting a delivered tree leaves it
  byte-for-byte unchanged and works even when the source is read-only.
- `pack` no longer holds a SQLite connection open across the worker pool (a
  forked child could finalise the inherited connection and corrupt the WAL); the
  catalog is opened, written, and closed around each phase.
- `pack`/`unpack` now abort *before* transporting when any item fails, instead of
  pushing a known-incomplete set and then erroring.
- The `pack`/`unpack` CLI reports transport/OS/SQLite errors cleanly instead of
  dumping a traceback.
- `tar` exit code 1 ("a file changed as we read it") is tolerated with a warning
  rather than failing the item; error paths now close pipes and remove partial
  outputs.

## [1.8.6] – 2026-05-02

Released as a `1.8.x` series: PyPI would not let `1.8` / `1.8.0` be reused after
deletion, so the first published artifact was `1.8.1`, then `1.8.3`, with `1.8.6`
the final tagged release.

### Added
- **Zsh completions** alongside bash, with a separate installer script for shell
  completions and a `--show` option; completions help/message updates.

### Changed
- **Dropped the PyNaCl dependency** in favour of a specialised C extension binding
  directly to libsodium — PyNaCl allocated fresh `bytes` buffers, so cipherdata is
  now handled in a reused `bytearray` (notably better for large files) and the
  `cipher_chunker` is gone. The build finds libsodium either system-wide
  (`SODIUM_INSTALL=system`, using `CFLAGS`/`LDFLAGS`) or from a bundled copy.
- Packaging for PyPI: wheel builds (Python 3.9+), MANIFEST-based package data,
  trusted-publisher env vars, and PyPI badges/classifiers.
- Keygen internals updated; debug leftovers removed.

### Fixed
- Keygen `--force` / directory logic and file permissions (no longer relies on
  the umask).

## [1.7] – 2024-05-24

### Added
- **Separate header stream:** store the Crypt4GH header separately from the data,
  plus a CLI option to **re-encrypt only the header** (with an early bail-out
  path).
- Edit lists now allow `skip 0`.

### Changed
- Python 3.12 in CI; dropped Python 3.6.
- Error (instead of silent failure) when a public key does not exist.

### Fixed
- Removed stray use of temporary files in the tool and in the tests.

## [1.6] – 2022-08-10
### Fixed
- Keygen generates the private key before the public key.

## [1.5] – 2021-03-07
### Fixed
- Issue #27; refactored PEM loading to strip trailing newlines and blank lines.

## [1.4] – 2020-07-27
### Fixed
- Handling of an unencrypted ssh key.
### Changed
- More descriptive message for scrypt support; packaging updates.

## [1.2] – 2020-03-13

Released but never git-tagged. (There was no 1.3 release; the project went
1.2 → 1.4.)

### Added
- **Multiple recipients** (`--recipient` repeatable), with de-duplication.
- Generate a key on the fly if none is specified.
- `DEBUG` switch via an environment variable.

### Changed
- umask handling; bash-completion updates. Dropped the bundled LaTeX spec in
  favour of hts-specs.

## [1.1] – 2019-12-04

### Changed
- **Performance:** ChaCha20 encryption/decryption now uses the PyNaCl bindings
  instead of OpenSSL.
- Refactored `cli.py`; edit-list cleanup and an added assertion.

### Fixed
- Prompt for an empty passphrase.

## [1.0] – 2019-12-01

- Initial public release of the Crypt4GH reference utility: streaming
  `encrypt` / `decrypt` / `reencrypt`, X25519 + ChaCha20-Poly1305, Crypt4GH and
  OpenSSH key formats, `crypt4gh-keygen`, and the edit-list oracle.

[Unreleased]: https://github.com/EGA-archive/crypt4gh/compare/v1.8.6...HEAD
[1.8.6]: https://github.com/EGA-archive/crypt4gh/releases/tag/v1.8.6
[1.7]: https://github.com/EGA-archive/crypt4gh/releases/tag/v1.7
[1.6]: https://github.com/EGA-archive/crypt4gh/releases/tag/v1.6
[1.5]: https://github.com/EGA-archive/crypt4gh/releases/tag/v1.5
[1.4]: https://github.com/EGA-archive/crypt4gh/releases/tag/v1.4
[1.2]: https://github.com/EGA-archive/crypt4gh/commits/v1.4
[1.1]: https://github.com/EGA-archive/crypt4gh/releases/tag/v1.1
[1.0]: https://github.com/EGA-archive/crypt4gh/releases/tag/v1.0
