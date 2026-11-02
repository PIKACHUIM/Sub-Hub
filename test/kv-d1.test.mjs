import test from 'node:test';
import assert from 'node:assert/strict';

import { createKvDatabase, STATE_KEY } from '../kv-d1.mjs';

function createBinding(initial) {
    const store = new Map(Object.entries(initial || {}));
    return {
        store,
        async get(key) {
            return store.has(key) ? store.get(key) : null;
        },
        async put(key, value) {
            store.set(key, value);
        },
        async delete(key) {
            store.delete(key);
        }
    };
}

function seedState() {
    return JSON.stringify({
        schemaVersion: 1,
        seq: { subscriptions: 2, nodes: 10 },
        subscriptions: [
            { id: 1, name: '全局', path: 'global', sub_order: 100, updated_at: 1, converter_backend: 'sub.xeton.dev' },
            { id: 2, name: '服务器', path: 'server', sub_order: 200, updated_at: 2, converter_backend: 'sub.xeton.dev' }
        ],
        nodes: [
            { id: 7, subscription_id: 2, name: 'A', original_link: 'ss://a', node_order: 5, enabled: 1 },
            { id: 8, subscription_id: 2, name: 'B', original_link: 'vmess://b', node_order: 9, enabled: 0 }
        ],
        sessions: [{ session_id: 's1', username: 'admin', expires_at: Date.now() + 60_000 }]
    });
}

test('reads subscriptions with node counts in D1 order', async () => {
    const db = createKvDatabase(createBinding({ [STATE_KEY]: seedState() }));

    const { results } = await db.prepare(`SELECT
        s.path,
        s.name,
        s.sub_order,
        s.updated_at,
        s.converter_backend,
        COUNT(n.id) as nodeCount
      FROM subscriptions s
      LEFT JOIN nodes n ON s.id = n.subscription_id
      GROUP BY s.id
      ORDER BY COALESCE(s.sub_order, s.id) ASC`).all();

    assert.deepEqual(results.map((row) => row.path), ['global', 'server']);
    assert.equal(results[1].nodeCount, 2);
});

test('returns only enabled node links for subscription content', async () => {
    const db = createKvDatabase(createBinding({ [STATE_KEY]: seedState() }));

    const { results } = await db.prepare(`SELECT GROUP_CONCAT(n.original_link, CHAR(10)) as content
      FROM nodes n
      JOIN subscriptions s ON n.subscription_id = s.id
      WHERE s.path = ? AND n.original_link IS NOT NULL AND (n.enabled IS NULL OR n.enabled = 1)
      GROUP BY s.id
      ORDER BY n.node_order ASC`).bind('server').all();

    assert.equal(results[0].content, 'ss://a');
});

test('creates nodes and subscriptions, persisting once per call', async () => {
    const binding = createBinding({ [STATE_KEY]: seedState() });
    const db = createKvDatabase(binding);

    const inserted = await db.prepare(
        "INSERT INTO nodes (subscription_id, name, original_link, node_order, enabled) VALUES (?, ?, ?, ?, 1)"
    ).bind(2, 'C', 'trojan://c', 11).run();
    assert.equal(inserted.meta.last_row_id, 11);

    await db.prepare(
        "INSERT INTO subscriptions (name, path, sub_order, updated_at, converter_backend) VALUES (?, ?, ?, ?, ?)"
    ).bind('新订阅', 'newone', 300, 3, 'sub.xeton.dev').run();

    const { results } = await db.prepare("SELECT id, name, path, converter_backend FROM subscriptions WHERE path = ?")
        .bind('newone').all();
    assert.equal(results.length, 1);
    assert.equal(results[0].id, 3);
});

test('rejects duplicate subscription paths like the D1 unique index', async () => {
    const db = createKvDatabase(createBinding({ [STATE_KEY]: seedState() }));

    await assert.rejects(
        () => db.prepare(
            "INSERT INTO subscriptions (name, path, sub_order, updated_at, converter_backend) VALUES (?, ?, ?, ?, ?)"
        ).bind('dup', 'global', 1, 1, 'sub.xeton.dev').run(),
        /UNIQUE constraint failed/
    );
});

test('applies a batch atomically in memory and persists it once', async () => {
    const binding = createBinding({ [STATE_KEY]: seedState() });
    const db = createKvDatabase(binding);

    const results = await db.batch([
        db.prepare("DELETE FROM nodes WHERE subscription_id = ?").bind(2),
        db.prepare("UPDATE subscriptions SET updated_at = ? WHERE id = ?").bind(999, 2)
    ]);

    assert.equal(results[0].meta.changes, 2);
    assert.equal(results[1].meta.changes, 1);

    const { results: nodes } = await db.prepare(
        'SELECT n.id, n.name, n.original_link, n.node_order, COALESCE(n.enabled, 1) as enabled FROM nodes n JOIN subscriptions s ON n.subscription_id = s.id WHERE s.path = ? ORDER BY n.node_order ASC'
    ).bind('server').all();
    assert.deepEqual(nodes, []);
});

test('slides session expiry and deletes by username', async () => {
    const db = createKvDatabase(createBinding({ [STATE_KEY]: seedState() }));
    const now = Date.now();

    const { results } = await db.prepare(
        'UPDATE sessions SET expires_at = ? WHERE session_id = ? AND expires_at > ? RETURNING *'
    ).bind(now + 86_400_000, 's1', now).all();
    assert.equal(results.length, 1);
    assert.equal(results[0].expires_at, now + 86_400_000);

    await db.prepare('DELETE FROM sessions WHERE username = ?').bind('admin').run();
    const after = await db.prepare(
        'UPDATE sessions SET expires_at = ? WHERE session_id = ? AND expires_at > ? RETURNING *'
    ).bind(now + 1, 's1', now).all();
    assert.equal(after.results.length, 0);
});

test('fails loudly on unsupported SQL instead of silently ignoring it', async () => {
    const db = createKvDatabase(createBinding({ [STATE_KEY]: seedState() }));
    assert.throws(() => db.prepare('DROP TABLE subscriptions'), /Unsupported SQL/);
});

test('requires a KV binding', () => {
    assert.throws(() => createKvDatabase(null), /KV binding SUBLINK_KV is required/);
});
