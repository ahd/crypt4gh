# -*- coding: utf-8 -*-
"""SQLite state catalog for pack/unpack runs.

Lives at ``<working>/catalog.sqlite``.  It records, per item, the source
size/mtime/mode, the plaintext and ciphertext SHA-256, the pack options and the
processing state.  This is the durable basis for a future ``--resume`` (skip
items already ``done`` whose source is unchanged) and for end-to-end integrity
verification on ``unpack``.

The catalog is owned and written by the orchestrator's main process only
(workers return results which the main process records).  The connection is
never held open across a worker pool (a forked child could finalise an inherited
SQLite connection and corrupt the WAL), so the orchestrator opens it, writes,
and closes it around each phase.  ``unpack`` opens the *source* catalog
``readonly=True`` so decrypting never mutates the delivered ciphertext.
"""

import os
import sqlite3
import json
import time
import logging
from urllib.request import pathname2url

LOG = logging.getLogger(__name__)

SCHEMA_VERSION = 1

_SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS run (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    direction    TEXT NOT NULL,          -- 'pack' | 'unpack'
    source       TEXT NOT NULL,
    dest         TEXT NOT NULL,
    options_json TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS item (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL REFERENCES run(id),
    relpath        TEXT NOT NULL,         -- source-relative (POSIX)
    kind           TEXT NOT NULL,         -- 'file' | 'tar' | 'dir' | 'symlink'
    codec          TEXT NOT NULL DEFAULT 'none',
    codec_level    INTEGER,
    src_size       INTEGER,
    src_mtime      REAL,
    src_mode       INTEGER,
    src_sha256     TEXT,
    symlink_target TEXT,
    cipher_relpath TEXT,
    cipher_size    INTEGER,
    cipher_sha256  TEXT,
    recipients_json TEXT,
    status         TEXT NOT NULL DEFAULT 'pending',
    error          TEXT,
    started_at     REAL,
    finished_at    REAL,
    UNIQUE (run_id, relpath)
);

CREATE INDEX IF NOT EXISTS item_status ON item(run_id, status);
'''


class Catalog:
    def __init__(self, path, readonly=False):
        self.path = str(path)
        self.readonly = readonly
        if readonly:
            # Open the database read-only and immutable, so reading a delivered
            # ciphertext catalog never modifies it -- not even the -wal/-shm
            # sidecars that a plain read-only open of a WAL database would create.
            # (Our catalogs are always cleanly checkpointed on close, so there is
            # no pending WAL for `immutable=1` to skip.)
            uri = 'file:' + pathname2url(os.path.abspath(self.path)) + '?mode=ro&immutable=1'
            self._db = sqlite3.connect(uri, uri=True)
            self._db.row_factory = sqlite3.Row
            return
        self._db = sqlite3.connect(self.path)
        self._db.row_factory = sqlite3.Row
        self._db.execute('PRAGMA journal_mode=WAL')
        self._db.execute('PRAGMA foreign_keys=ON')
        self._db.executescript(_SCHEMA)
        self._db.execute(
            'INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)',
            ('schema_version', str(SCHEMA_VERSION)),
        )
        self._db.commit()

    # -- runs ------------------------------------------------------------
    def start_run(self, direction, source, dest, options, tool_version):
        cur = self._db.execute(
            'INSERT INTO run(direction, source, dest, options_json, tool_version, created_at) '
            'VALUES (?,?,?,?,?,?)',
            (direction, source, dest, json.dumps(options, sort_keys=True), tool_version, time.time()),
        )
        self._db.commit()
        return cur.lastrowid

    # -- items -----------------------------------------------------------
    def add_item(self, run_id, entry):
        """Insert (or replace) a pending item row from an enumeration entry (a dict)."""
        self._db.execute(
            'INSERT OR REPLACE INTO item '
            '(run_id, relpath, kind, codec, codec_level, src_size, src_mtime, src_mode, '
            ' symlink_target, cipher_relpath, recipients_json, status) '
            'VALUES (:run_id,:relpath,:kind,:codec,:codec_level,:src_size,:src_mtime,:src_mode,'
            ':symlink_target,:cipher_relpath,:recipients_json,:status)',
            {
                'run_id': run_id,
                'relpath': entry['relpath'],
                'kind': entry['kind'],
                'codec': entry.get('codec', 'none'),
                'codec_level': entry.get('codec_level'),
                'src_size': entry.get('src_size'),
                'src_mtime': entry.get('src_mtime'),
                'src_mode': entry.get('src_mode'),
                'symlink_target': entry.get('symlink_target'),
                'cipher_relpath': entry.get('cipher_relpath'),
                'recipients_json': entry.get('recipients_json'),
                'status': entry.get('status', 'pending'),
            },
        )
        self._db.commit()

    def finish_item(self, run_id, relpath, **fields):
        fields.setdefault('finished_at', time.time())
        cols = ', '.join(f'{k}=:{k}' for k in fields)
        params = dict(fields, run_id=run_id, relpath=relpath)
        self._db.execute(
            f'UPDATE item SET {cols} WHERE run_id=:run_id AND relpath=:relpath', params
        )
        self._db.commit()

    def get_item(self, run_id, relpath):
        row = self._db.execute(
            'SELECT * FROM item WHERE run_id=? AND relpath=?', (run_id, relpath)
        ).fetchone()
        return dict(row) if row else None

    def items(self, run_id, status=None):
        if status is None:
            rows = self._db.execute('SELECT * FROM item WHERE run_id=? ORDER BY id', (run_id,))
        else:
            rows = self._db.execute(
                'SELECT * FROM item WHERE run_id=? AND status=? ORDER BY id', (run_id, status)
            )
        return [dict(r) for r in rows]

    def counts(self, run_id):
        rows = self._db.execute(
            'SELECT status, COUNT(*) n FROM item WHERE run_id=? GROUP BY status', (run_id,)
        )
        return {r['status']: r['n'] for r in rows}

    def latest_run(self, direction=None):
        if direction:
            row = self._db.execute(
                'SELECT * FROM run WHERE direction=? ORDER BY id DESC LIMIT 1', (direction,)
            ).fetchone()
        else:
            row = self._db.execute('SELECT * FROM run ORDER BY id DESC LIMIT 1').fetchone()
        return dict(row) if row else None

    def close(self):
        self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
