-- Sub-Hub 数据库初始化脚本
-- 用于初始化 Cloudflare D1 数据库

-- 订阅表
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  name TEXT NOT NULL, 
  path TEXT NOT NULL UNIQUE, 
  sub_order INTEGER DEFAULT 0, 
  updated_at INTEGER, 
  converter_backend TEXT DEFAULT 'sub.xeton.dev'
);

-- 节点表
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  subscription_id INTEGER NOT NULL, 
  name TEXT NOT NULL, 
  original_link TEXT NOT NULL, 
  node_order INTEGER NOT NULL DEFAULT 0, 
  enabled INTEGER DEFAULT 1, 
  FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

-- 会话表
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY, 
  username TEXT NOT NULL, 
  expires_at INTEGER NOT NULL
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_subscriptions_path ON subscriptions(path);
CREATE INDEX IF NOT EXISTS idx_nodes_subscription_order ON nodes(subscription_id, node_order);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- 插入默认订阅（可选）
-- INSERT INTO subscriptions (name, path, sub_order, updated_at) VALUES ('默认订阅', 'default', 0, strftime('%s', 'now'));