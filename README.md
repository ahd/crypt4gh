[![Documentation Status](https://readthedocs.org/projects/crypt4gh/badge/?version=latest)](https://crypt4gh.readthedocs.io/en/latest/?badge=latest)
[![Testsuite](https://github.com/EGA-archive/crypt4gh/workflows/Testsuite/badge.svg)](https://github.com/EGA-archive/crypt4gh/actions)
[![PyPI version](https://img.shields.io/pypi/v/crypt4gh)](https://pypi.org/project/crypt4gh/)
[![Python versions](https://img.shields.io/pypi/pyversions/crypt4gh)](https://pypi.org/project/crypt4gh/)

# Crypt4GH Encryption Utility

`crypt4gh` is a Python tool to encrypt, decrypt or re-encrypt files, according to the [GA4GH encryption file format](https://www.ga4gh.org/news/crypt4gh-a-secure-method-for-sharing-human-genetic-data/).


## Installation

Python `3.6+` required to use the crypt4gh encryption utility.

Install it from PyPI:

```
pip install crypt4gh
```

or [compile and install it from the latest sources](#compilation-from-sources)


## Usage

The usual `-h` flag shows you the different options that the tool accepts.

```bash
$ crypt4gh -h

Utility for the cryptographic GA4GH standard, reading from stdin and outputting to stdout.

Whole directory trees (local, ssh or Globus; parallel, with a catalog):
   crypt4gh pack [options] <source> <dest>      see: crypt4gh pack --help
   crypt4gh unpack [options] <source> <dest>    see: crypt4gh unpack --help

Usage:
   {PROG} [-hv] [--log <file>] encrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--range <start-end>]  [--header <path>]
   {PROG} [-hv] [--log <file>] decrypt [--sk <path>] [--sender_pk <path>] [--range <start-end>]
   {PROG} [-hv] [--log <file>] rearrange [--sk <path>] --range <start-end>
   {PROG} [-hv] [--log <file>] reencrypt [--sk <path>] --recipient_pk <path> [--recipient_pk <path>]... [--trim] [--header-only]

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <file>           Path to a logging configuration file (JSON, logging.config.dictConfig)
   --sk <keyfile>         Curve25519-based Private key.
                          When encrypting, if neither the private key nor C4GH_SECRET_KEY are specified, we generate a new key 
   --recipient_pk <path>  Recipient's Curve25519-based Public key
   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (akin to signature)
   --range <start-end>    Byte-range either as  <start-end> or just <start> (Start included, End excluded)
   -t, --trim             Keep only header packets that you can decrypt
   --header <path>        Where to write the header (default: stdout)
   --header-only          Whether the input data consists only of a header (default: false)


Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${C4GH_SECRET_KEY})
   C4GH_PASSPHRASE  If defined, it will be used as the passphrase
                    for decoding the secret key, replacing the callback.
                    Note: this is insecure. Only used for testing
   C4GH_DEBUG       If True, it will print (a lot of) debug information.
                    (Watch out: the output contains secrets)
 
```

## Demonstration

Alice and Bob generate both a pair of public/private keys.

```bash
$ crypt4gh-keygen --sk alice.sec --pk alice.pub
$ crypt4gh-keygen --sk bob.sec --pk bob.pub
```

Bob encrypts a file for Alice:

```bash
$ crypt4gh encrypt --sk bob.sec --recipient_pk alice.pub < file > file.c4gh
```

Alice decrypts the encrypted file:

```bash
$ crypt4gh decrypt --sk alice.sec < file.c4gh
```

[![asciicast](https://asciinema.org/a/mmCBfBdCFfcYCRBuTSe3kjCFs.svg)](https://asciinema.org/a/mmCBfBdCFfcYCRBuTSe3kjCFs)

## Encrypting a whole directory

The `pack` and `unpack` verbs work on directory trees instead of a single
stream. `pack` recursively encrypts a source tree into a target tree, leaving
the source plaintext untouched; `unpack` reverses it.

```bash
# Encrypt every file in ./data for Alice, mirroring the tree into ./vault
$ crypt4gh pack --sk bob.sec --recipient_pk alice.pub ./data ./vault

# Decrypt it back
$ crypt4gh unpack --sk alice.sec ./vault ./restored
```

`crypt4gh pack --help` and `crypt4gh unpack --help` describe every option,
environment variable and endpoint form. In short:

* `--sk` is your secret key: the *sender* for `pack`, the *recipient* for
  `unpack`. It defaults to `$C4GH_SECRET_KEY`, and the passphrase is prompted
  for, or taken from `$C4GH_PASSPHRASE`, which is insecure.
  `--recipient_pk` (for `pack`, repeatable) says who can decrypt.
  `--sender_pk` (for `unpack`, optional) rejects anything that was not
  encrypted by that sender.
* `--tar` bundles each top-level subdirectory into a single tar archive before
  encryption (loose files at the root are still encrypted individually).
* `--compress none|gzip|bzip2|zstd` compresses tarred subdirectories between
  tarring and encryption, with an optional level (e.g. `--compress zstd:19`).
  The default is `none` (genomic payloads are usually already compressed).
* Source or destination may be a remote, rsync-style `[user@]host:/path`.
  Ciphertext is staged in a local working directory and moved with rsync over
  ssh. A remote *source* is streamed over ssh, so its plaintext is never
  written to disk here.
* `--working DIR` sets the staging directory. For `pack` the default is the
  destination when it is local. Otherwise, and always for `unpack`, the
  default is `$C4GH_WORKDIR`, or else `./crypt4gh-work`. It must hold the
  whole staged set.
* `--jobs N` sets the number of parallel workers (default `min(cpu_count, 8)`).
* `-v` and `-vv` add progress and debug output on the terminal. `--log FILE`
  (default `$C4GH_LOG`) also logs the run to a file (see below).

Each run writes a SQLite catalog (`<working>/catalog.sqlite`) recording every
item's size, mtime, mode and plaintext/ciphertext SHA-256 — used for integrity
verification, and the basis for resumable runs.

### Globus endpoints (`globus:` transport)

Either the source or the destination may be a Globus collection, addressed as
`globus:<endpoint-id>:/path`:

```bash
# pack a tree and push the ciphertext to a Globus collection
crypt4gh pack --recipient_pk bob.pub ./data globus:<COLLECTION-ID>:/incoming/

# pull ciphertext from a collection and unpack it locally
crypt4gh unpack --sk mysecret.key globus:<COLLECTION-ID>:/incoming/ ./out
```

Globus moves files *at rest* between two endpoints, so the local side of the
transfer is this host's Globus Connect Personal (GCP) endpoint. crypt4gh manages
that endpoint for you. Before a `globus:` transfer it:

- resolves the local endpoint;
- **shares the working directory** with it, via GCP `-restrict-paths`. This
  restarts the endpoint, and crypt4gh waits for the old instance to exit
  first;
- **starts the endpoint if it is not running**;
- waits until the Globus service can actually reach the endpoint, not just
  until its local status says "connected". If it never becomes reachable,
  crypt4gh restarts it once, then gives up with a clear error.

The transfer itself is recursive with `--sync-level checksum`, and its final
status must be SUCCEEDED. The endpoint is discovered in this order:

1. `--globus-endpoint ID` or `C4GH_GLOBUS_LOCAL_ENDPOINT=<endpoint-id>`
   (explicit override; give `--globus-config-dir` too for an isolated
   endpoint);
2. the state file `~/.config/crypt4gh/globus.json` written by
   `crypt4gh-install-gcp --ensure-usable` (records the endpoint id, its config
   dir, and shared paths — the only way to find an isolated `-dir` endpoint);
3. `globus endpoint local-id` (the default GCP endpoint).

If none is configured, crypt4gh stops with a clear error rather than guessing,
unless you opt into auto-install with `--install-gcp` or
`C4GH_GLOBUS_AUTO_INSTALL=1`. That lets it install and register a fresh
endpoint on the spot (named by `--globus-endpoint-name`, default
`crypt4gh-<hostname>`). You need an authenticated `globus` CLI either way
(`globus login`).

> **Speed note.** GridFTP throughput needs a data-transfer server at *both* ends,
> so `--working` must live on storage the local endpoint exposes. crypt4gh shares
> the working directory automatically; if it sits on storage no reachable
> collection can see, the transfer would otherwise fall back or fail, and you are
> warned.

**Troubleshooting.**
- The endpoint's own output goes to `<config-dir>/gcp-start.log` (by default
  `~/.local/share/gcp/config/gcp-start.log`). An error that crypt4gh raises
  about the endpoint quotes the last lines of that log.
- To check the endpoint by hand, compare
  `globusconnectpersonal -dir <config-dir> -status` (the local view) with
  `globus endpoint show <id>` (look for `GCP Connected`) and
  `globus ls <id>:/` (the Globus service's view).
- A 502 `GCDisconnected` means the Globus service can't see the endpoint,
  whatever its local status says.

### Logging

`pack`/`unpack` send the whole run to `--log FILE`, or to `$C4GH_LOG` if that
is set. This covers the directory walk and tree set-up, every pool worker,
Globus endpoint management, transfers (task ids and outcomes) and the final
result:

- If FILE is a JSON `logging.config` dictConfig document, it is applied, as
  for the streaming verbs' `--log`.
- Otherwise records are appended to FILE with timestamps and process names.
  The file gets INFO whatever `-v` says, or DEBUG with `-vv`, which adds a line
  per item.

```bash
crypt4gh pack -v --log ~/pack-$(date +%F).log --sk me.sec --recipient_pk them.pub \
    --working /scratch/w0 ./data globus:<COLLECTION-ID>:/incoming/
```

### Installing Globus Connect Personal (Linux)

If the remote already exposes a Globus collection you need install nothing
locally; otherwise stand up a transient personal endpoint. The one-shot path
installs, registers and starts a connected endpoint (and records it in the state
file above):

```bash
crypt4gh-install-gcp --ensure-usable
```

Re-running it against an endpoint that is already registered or running is
safe. It starts nothing new, and it records that endpoint in the state file:
the id is read from `<config-dir>/lta/client-id.txt`. This is how you adopt an
endpoint that was set up by hand.

Globus Connect Personal is closed-source vendor software (~100 MB), so it is not
bundled here. To install only the binary:

```bash
crypt4gh-install-gcp            # or: python -m crypt4gh.pack.gcp_install
```

This is a no-op if `globusconnectpersonal` is already on your `PATH`. Otherwise
it downloads the current stable Linux build, unpacks it under
`~/.local/share/gcp/`, and links the launcher at
`~/.local/bin/globusconnectpersonal`. Useful flags:

* `--force` — reinstall even if one is already on `PATH`.
* `--sha256 <hex>` — verify the download against a pinned checksum (the tool
  prints the SHA-256 it fetched so you can pin it next time).
* `--setup-key <KEY>` — register the endpoint straight away using a setup key
  from <https://app.globus.org/collections?add>.
* `--start` — start the endpoint after installing (and registering). It runs
  in the background, and the command returns once the endpoint is connected.
* `--dir DIR` — the config directory used by `--setup-key`, `--start`,
  `--stop` and `--ensure-usable` (`--ensure-usable` defaults to
  `~/.local/share/gcp/config`).
* `--stop` — stop the endpoint and wait until it has really exited.

Registration still needs that one-time setup key (Globus has no fully headless
sign-up). After installing:

```bash
# 1. Create a collection + setup key at https://app.globus.org/collections?add
globusconnectpersonal -setup --setup-key <KEY>
globusconnectpersonal -start &
```

## File Format

Refer to the [specifications](http://samtools.github.io/hts-specs/crypt4gh.pdf) or this [documentation](https://crypt4gh.readthedocs.io/en/latest/encryption.html).

## Compilation from sources

Get the source code, and install the python dependencies with:

```
git clone --recursive https://github.com/EGA-archive/crypt4gh
pip install -r crypt4gh/requirements.txt
```

The Crypt4GH python package relies on
[libsodium](https://libsodium.org), a portable C library. A copy is
bundled with Crypt4GH as a submodule. You can either use the version
of libsodium already installed on your system (eg, provided by your
distribution), or use the bundled version.

For the system-wide version, you use the `SODIUM_INSTALL=system` environment variable. You might also need to adjust the `CFLAGS` and `LDFLAGS` environment variables. For example, using `pkg-config` to find the libsodium headers and library, you can use:

```
export SODIUM_INSTALL=system
# If not installed in default locations
export CFLAGS="$(pkg-config --cflags libsodium)"
export LDFLAGS="$(pkg-config --libs libsodium)"
```

If you want to use the bundled version, skip those environment variables.

Finally, run

```
pip install ./crypt4gh
```

## Development with uv

The project ships a `pyproject.toml` and a `uv.lock`. To set up a development
environment and run the tests (Python 3.13+):

```bash
# Against a system-installed libsodium (recommended for development)
export SODIUM_INSTALL=system
export CFLAGS="$(pkg-config --cflags libsodium)"
export LDFLAGS="$(pkg-config --libs libsodium)"

uv sync                 # create the venv and build the C extension
uv run pytest tests/unit    # Python unit tests
bats tests                  # end-to-end tests (requires bats)
```

To build against the bundled libsodium instead, initialise the submodule
(`git submodule update --init`) and drop `SODIUM_INSTALL=system`.

## Shell completions

If you want auto-completions, you can install extra scripts with the utility `crypt4gh-completions`.

For example, you can install the `bash` completion scripts with:

	crypt4gh-completions install bash

This will install in `~/.local/share/bash-completion/completions` (ie, the default location for 'bash-completion >= 2.x').

Or specify the target directory, eg

	crypt4gh-completions install bash --target /etc/bash_completion.d

So far, we provide the `bash` and `zsh` completions. Help me out with a PR for the other shells.

List default locations and scripts with:

	crypt4gh-completions show
