// KV-backed data layer for Sub-Hub.
// The Worker keeps calling env.DB with the same SQL it used on D1; this module
// answers those statements from one KV snapshot key so a request is a single
// read plus at most one write (matching D1 batch semantics without a database).

export const STATE_KEY = 'subhub:v1:db';

const EMPTY_STATE = () => ({
    schemaVersion: 1,
    seq: { subscriptions: 0, nodes: 0 },
    subscriptions: [],
    nodes: [],
    sessions: []
});

function normalizeSql(sql) {
    return String(sql)
        .replace(/--[^\n]*/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

function nodeCountFor(state, subscriptionId) {
    return state.nodes.filter((node) => node.subscription_id === subscriptionId).length;
}

function findSubscriptionByPath(state, path) {
    return state.subscriptions.find((item) => item.path === path) || null;
}

function toSubscriptionResponse(state, subscription) {
    return {
        id: subscription.id,
        name: subscription.name,
        path: subscription.path,
        sub_order: subscription.sub_order,
        updated_at: subscription.updated_at,
        converter_backend: subscription.converter_backend,
        nodeCount: nodeCountFor(state, subscription.id)
    };
}

const HANDLERS = [
    {
        match: /^SELECT id FROM subscriptions WHERE path = \?$/i,
        read: (state, [path]) => {
            const subscription = findSubscriptionByPath(state, path);
            return { results: subscription ? [{ id: subscription.id }] : [] };
        }
    },
    {
        match: /^SELECT COUNT\(\*\) as count FROM subscriptions WHERE path = \?$/i,
        read: (state, [path]) => ({ results: [{ count: findSubscriptionByPath(state, path) ? 1 : 0 }] })
    },
    {
        match: /^SELECT \* FROM subscriptions WHERE path = \?$/i,
        read: (state, [path]) => {
            const subscription = findSubscriptionByPath(state, path);
            return { results: subscription ? [structuredClone(subscription)] : [] };
        }
    },
    {
        match: /^SELECT 1 FROM subscriptions WHERE path = \? LIMIT 1$/i,
        read: (state, [path]) => ({ results: findSubscriptionByPath(state, path) ? [{ 1: 1 }] : [] })
    },
    {
        match: /^SELECT id, name, path, converter_backend FROM subscriptions WHERE path = \?$/i,
        read: (state, [path]) => {
            const subscription = findSubscriptionByPath(state, path);
            if (!subscription) return { results: [] };
            const { id, name, path: storedPath, converter_backend } = subscription;
            return { results: [{ id, name, path: storedPath, converter_backend }] };
        }
    },
    {
        match: /^SELECT s\.path, s\.name, s\.sub_order, s\.updated_at, s\.converter_backend, COUNT\(n\.id\) as nodeCount FROM subscriptions s LEFT JOIN nodes n ON s\.id = n\.subscription_id GROUP BY s\.id ORDER BY COALESCE\(s\.sub_order, s\.id\) ASC$/i,
        read: (state) => {
            const rows = [...state.subscriptions]
                .sort((left, right) => {
                    const leftKey = left.sub_order === null || left.sub_order === undefined ? left.id : left.sub_order;
                    const rightKey = right.sub_order === null || right.sub_order === undefined ? right.id : right.sub_order;
                    return leftKey - rightKey;
                })
                .map((subscription) => toSubscriptionResponse(state, subscription));
            return { results: rows };
        }
    },
    {
        match: /^SELECT n\.id, n\.name, n\.original_link, n\.node_order, COALESCE\(n\.enabled, 1\) as enabled FROM nodes n JOIN subscriptions s ON n\.subscription_id = s\.id WHERE s\.path = \? ORDER BY n\.node_order ASC$/i,
        read: (state, [path]) => {
            const subscription = findSubscriptionByPath(state, path);
            if (!subscription) return { results: [] };
            const rows = state.nodes
                .filter((node) => node.subscription_id === subscription.id)
                .sort((left, right) => left.node_order - right.node_order)
                .map((node) => ({
                    id: node.id,
                    name: node.name,
                    original_link: node.original_link,
                    node_order: node.node_order,
                    enabled: node.enabled === null || node.enabled === undefined ? 1 : node.enabled
                }));
            return { results: rows };
        }
    },
    {
        match: /^SELECT GROUP_CONCAT\(n\.original_link, CHAR\(10\)\) as content FROM nodes n JOIN subscriptions s ON n\.subscription_id = s\.id WHERE s\.path = \? AND n\.original_link IS NOT NULL AND \(n\.enabled IS NULL OR n\.enabled = 1\) GROUP BY s\.id ORDER BY n\.node_order ASC$/i,
        read: (state, [path]) => {
            const subscription = findSubscriptionByPath(state, path);
            if (!subscription) return { results: [] };
            const links = state.nodes
                .filter((node) => node.subscription_id === subscription.id && node.original_link)
                .filter((node) => node.enabled === null || node.enabled === undefined || node.enabled === 1)
                .sort((left, right) => left.node_order - right.node_order)
                .map((node) => node.original_link);
            return { results: links.length ? [{ content: links.join('\n') }] : [] };
        }
    },
    {
        match: /^UPDATE sessions SET expires_at = \? WHERE session_id = \? AND expires_at > \? RETURNING \*$/i,
        write: (state, [expiresAt, sessionId, now]) => {
            const session = state.sessions.find((item) => item.session_id === sessionId);
            if (!session || !(session.expires_at > now)) return { results: [] };
            session.expires_at = expiresAt;
            return { results: [structuredClone(session)] };
        }
    },
    {
        match: /^INSERT INTO subscriptions \(name, path, sub_order, updated_at, converter_backend\) VALUES \(\?, \?, \?, \?, \?\)$/i,
        write: (state, [name, path, subOrder, updatedAt, backend]) => {
            if (findSubscriptionByPath(state, path)) {
                throw new Error('UNIQUE constraint failed: subscriptions.path');
            }
            const id = ++state.seq.subscriptions;
            state.subscriptions.push({ id, name, path, sub_order: subOrder, updated_at: updatedAt, converter_backend: backend });
            return { lastRowId: id, changes: 1 };
        }
    },
    {
        match: /^UPDATE subscriptions SET sub_order = \? WHERE path = \?$/i,
        write: (state, [order, path]) => {
            const subscription = findSubscriptionByPath(state, path);
            if (!subscription) return { changes: 0 };
            subscription.sub_order = order;
            return { changes: 1 };
        }
    },
    {
        match: /^UPDATE subscriptions SET updated_at = \? WHERE id = \?$/i,
        write: (state, [updatedAt, id]) => {
            const subscription = state.subscriptions.find((item) => item.id === Number(id));
            if (!subscription) return { changes: 0 };
            subscription.updated_at = updatedAt;
            return { changes: 1 };
        }
    },
    {
        match: /^UPDATE subscriptions SET name = \?, path = \?, converter_backend = \? WHERE path = \?$/i,
        write: (state, [name, newPath, backend, path]) => {
            const subscription = findSubscriptionByPath(state, path);
            if (!subscription) return { changes: 0 };
            if (newPath !== path && findSubscriptionByPath(state, newPath)) {
                throw new Error('UNIQUE constraint failed: subscriptions.path');
            }
            subscription.name = name;
            subscription.path = newPath;
            subscription.converter_backend = backend;
            return { changes: 1 };
        }
    },
    {
        match: /^DELETE FROM subscriptions WHERE path = \?$/i,
        write: (state, [path]) => {
            const before = state.subscriptions.length;
            state.subscriptions = state.subscriptions.filter((item) => item.path !== path);
            return { changes: before - state.subscriptions.length };
        }
    },
    {
        match: /^INSERT INTO nodes \(subscription_id, name, original_link, node_order, enabled\) VALUES \(\?, \?, \?, \?, 1\)$/i,
        write: (state, [subscriptionId, name, originalLink, nodeOrder]) => {
            const id = ++state.seq.nodes;
            state.nodes.push({
                id,
                subscription_id: Number(subscriptionId),
                name,
                original_link: originalLink,
                node_order: nodeOrder,
                enabled: 1
            });
            return { lastRowId: id, changes: 1 };
        }
    },
    {
        match: /^DELETE FROM nodes WHERE subscription_id = \?$/i,
        write: (state, [subscriptionId]) => {
            const before = state.nodes.length;
            state.nodes = state.nodes.filter((node) => node.subscription_id !== Number(subscriptionId));
            return { changes: before - state.nodes.length };
        }
    },
    {
        match: /^DELETE FROM nodes WHERE subscription_id IN \(SELECT id FROM subscriptions WHERE path = \?\)$/i,
        write: (state, [path]) => {
            const subscription = findSubscriptionByPath(state, path);
            if (!subscription) return { changes: 0 };
            const before = state.nodes.length;
            state.nodes = state.nodes.filter((node) => node.subscription_id !== subscription.id);
            return { changes: before - state.nodes.length };
        }
    },
    {
        match: /^DELETE FROM nodes WHERE id IN \(([?, ]+)\) AND subscription_id = \?$/i,
        write: (state, params) => {
            const subscriptionId = Number(params[params.length - 1]);
            const ids = params.slice(0, -1).map(Number);
            const before = state.nodes.length;
            state.nodes = state.nodes.filter(
                (node) => !(ids.includes(node.id) && node.subscription_id === subscriptionId)
            );
            return { changes: before - state.nodes.length };
        }
    },
    {
        match: /^DELETE FROM nodes WHERE id = \? AND subscription_id = \( SELECT id FROM subscriptions WHERE path = \? LIMIT 1 \)$/i,
        write: (state, [nodeId, path]) => {
            const subscription = findSubscriptionByPath(state, path);
            if (!subscription) return { changes: 0 };
            const before = state.nodes.length;
            state.nodes = state.nodes.filter(
                (node) => !(node.id === Number(nodeId) && node.subscription_id === subscription.id)
            );
            return { changes: before - state.nodes.length };
        }
    },
    {
        match: /^UPDATE nodes SET node_order = \? WHERE id = \? AND subscription_id = \?$/i,
        write: (state, [order, id, subscriptionId]) => {
            const node = state.nodes.find(
                (item) => item.id === Number(id) && item.subscription_id === Number(subscriptionId)
            );
            if (!node) return { changes: 0 };
            node.node_order = order;
            return { changes: 1 };
        }
    },
    {
        match: /^UPDATE nodes SET enabled = \? WHERE id = \? AND subscription_id = \( SELECT id FROM subscriptions WHERE path = \? LIMIT 1 \)$/i,
        write: (state, [enabled, nodeId, path]) => {
            const subscription = findSubscriptionByPath(state, path);
            if (!subscription) return { changes: 0 };
            const node = state.nodes.find(
                (item) => item.id === Number(nodeId) && item.subscription_id === subscription.id
            );
            if (!node) return { changes: 0 };
            node.enabled = Number(enabled);
            return { changes: 1 };
        }
    },
    {
        match: /^UPDATE nodes SET original_link = \?, name = \? WHERE id = \? AND subscription_id = \?$/i,
        write: (state, [originalLink, name, nodeId, subscriptionId]) => {
            const node = state.nodes.find(
                (item) => item.id === Number(nodeId) && item.subscription_id === Number(subscriptionId)
            );
            if (!node) return { changes: 0 };
            node.original_link = originalLink;
            node.name = name;
            return { changes: 1 };
        }
    },
    {
        match: /^INSERT INTO sessions \(session_id, username, expires_at\) VALUES \(\?, \?, \?\)$/i,
        write: (state, [sessionId, username, expiresAt]) => {
            state.sessions = state.sessions.filter((item) => item.session_id !== sessionId);
            state.sessions.push({ session_id: sessionId, username, expires_at: expiresAt });
            return { changes: 1 };
        }
    },
    {
        match: /^DELETE FROM sessions WHERE expires_at < \?$/i,
        write: (state, [now]) => {
            const before = state.sessions.length;
            state.sessions = state.sessions.filter((item) => !(item.expires_at < now));
            return { changes: before - state.sessions.length };
        }
    },
    {
        match: /^DELETE FROM sessions WHERE username = \?$/i,
        write: (state, [username]) => {
            const before = state.sessions.length;
            state.sessions = state.sessions.filter((item) => item.username !== username);
            return { changes: before - state.sessions.length };
        }
    },
    {
        match: /^DELETE FROM sessions WHERE session_id = \?$/i,
        write: (state, [sessionId]) => {
            const before = state.sessions.length;
            state.sessions = state.sessions.filter((item) => item.session_id !== sessionId);
            return { changes: before - state.sessions.length };
        }
    }
];

function resolveHandler(sql) {
    const normalized = normalizeSql(sql);
    for (const handler of HANDLERS) {
        if (handler.match.test(normalized)) {
            return handler;
        }
    }
    // Fail loudly: silently ignoring a statement would corrupt state.
    throw new Error(`Unsupported SQL for KV backend: ${normalized}`);
}

function d1Result(result, changes = 0, lastRowId = 0) {
    return {
        success: true,
        results: result.results ?? [],
        meta: { changes, last_row_id: lastRowId }
    };
}

class Statement {
    constructor(db, sql) {
        this.db = db;
        this.sql = sql;
        this.params = [];
        this.handler = resolveHandler(sql);
    }

    bind(...params) {
        this.params = params;
        return this;
    }

    async all() {
        return this.db.executeOne(this);
    }

    async run() {
        return this.db.executeOne(this);
    }

    async first(column) {
        const result = await this.db.executeOne(this);
        const row = result.results?.[0] ?? null;
        return column ? row?.[column] ?? null : row;
    }
}

class KvDatabase {
    constructor(binding, options = {}) {
        if (!binding) {
            throw new Error('KV binding SUBLINK_KV is required');
        }
        this.binding = binding;
        this.stateKey = options.stateKey || STATE_KEY;
    }

    prepare(sql) {
        return new Statement(this, sql);
    }

    async loadState() {
        const stored = await this.binding.get(this.stateKey);
        if (!stored) {
            return { state: EMPTY_STATE(), mutated: false };
        }
        const state = typeof stored === 'string' ? JSON.parse(stored) : stored;
        return {
            state: {
                ...EMPTY_STATE(),
                ...state,
                seq: { ...EMPTY_STATE().seq, ...(state.seq || {}) }
            },
            mutated: false
        };
    }

    async saveState(state) {
        await this.binding.put(this.stateKey, JSON.stringify(state));
    }

    async executeOne(statement) {
        const { state } = await this.loadState();
        const handler = statement.handler;
        const params = statement.params;

        if (handler.read) {
            const result = handler.read(state, params);
            return d1Result(result);
        }

        const result = handler.write(state, params);
        await this.saveState(state);
        return d1Result(result, result.changes ?? 0, result.lastRowId ?? 0);
    }

    async batch(statements) {
        const { state } = await this.loadState();
        const results = statements.map((statement) => {
            const handler = statement.handler;
            if (handler.read) {
                return d1Result(handler.read(state, statement.params));
            }
            const result = handler.write(state, statement.params);
            return d1Result(result, result.changes ?? 0, result.lastRowId ?? 0);
        });

        const mutated = statements.some((statement) => Boolean(statement.handler.write));
        if (mutated) {
            await this.saveState(state);
        }
        return results;
    }

    async exec() {
        throw new Error('Multi-statement exec is not supported by the KV backend');
    }
}

export function createKvDatabase(binding, options) {
    return new KvDatabase(binding, options);
}
