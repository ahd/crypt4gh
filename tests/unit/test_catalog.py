# -*- coding: utf-8 -*-
from crypt4gh.pack.catalog import Catalog


def _entry(relpath, kind='file', **kw):
    base = {'relpath': relpath, 'kind': kind, 'cipher_relpath': relpath + '.c4gh',
            'src_size': 10, 'src_mtime': 1.0, 'src_mode': 0o644}
    base.update(kw)
    return base


def test_run_and_items(tmp_path):
    cat = Catalog(tmp_path / 'catalog.sqlite')
    run_id = cat.start_run('pack', '/src', '/dst', {'tar': False}, '1.8.6')
    assert run_id == 1

    cat.add_item(run_id, _entry('a.txt', status='pending'))
    cat.add_item(run_id, _entry('b.txt', status='pending'))
    assert cat.counts(run_id) == {'pending': 2}

    cat.finish_item(run_id, 'a.txt', status='done', src_sha256='deadbeef', cipher_size=42)
    assert cat.counts(run_id) == {'pending': 1, 'done': 1}

    a = cat.get_item(run_id, 'a.txt')
    assert a['status'] == 'done'
    assert a['src_sha256'] == 'deadbeef'
    assert a['cipher_size'] == 42
    assert a['src_mode'] == 0o644

    assert cat.latest_run('pack')['id'] == run_id
    cat.close()


def test_reopen_persists(tmp_path):
    path = tmp_path / 'catalog.sqlite'
    with Catalog(path) as cat:
        rid = cat.start_run('pack', '/s', '/d', {}, '1.8.6')
        cat.add_item(rid, _entry('x', status='done'))
    with Catalog(path) as cat:
        run = cat.latest_run()
        assert run['direction'] == 'pack'
        assert cat.items(run['id'])[0]['relpath'] == 'x'


def test_add_item_is_idempotent(tmp_path):
    """Re-adding the same relpath replaces it (basis for --resume re-runs)."""
    with Catalog(tmp_path / 'c.sqlite') as cat:
        rid = cat.start_run('pack', '/s', '/d', {}, '1.8.6')
        cat.add_item(rid, _entry('a', status='pending'))
        cat.add_item(rid, _entry('a', status='pending'))
        assert len(cat.items(rid)) == 1
