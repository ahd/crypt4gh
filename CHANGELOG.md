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

## [1.8.6]
- Zsh completions; completions help/message updates.

## [1.7] – [1.8.6]
- Multiple recipients, edit lists and rearrange, separate header/data handling,
  bundled libsodium build with `SODIUM_INSTALL=system` option. (See git history
  for details.)

## [1.0] – [1.6]
- Initial public releases of the Crypt4GH reference utility: streaming
  `encrypt` / `decrypt` / `reencrypt`, X25519 + ChaCha20-Poly1305, Crypt4GH and
  OpenSSH key formats, `crypt4gh-keygen`.

[Unreleased]: https://github.com/EGA-archive/crypt4gh/compare/v1.8.6...HEAD
[1.8.6]: https://github.com/EGA-archive/crypt4gh/releases/tag/v1.8.6
