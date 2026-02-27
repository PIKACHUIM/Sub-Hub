# Sub-Hub

Sub-Hub 是一个基于 Cloudflare Workers 的代理节点订阅管理系统。它提供了一个直观的 Web 界面，让您可以轻松管理多个订阅和节点。

[![Deploy to Cloudflare Workers](https://img.shields.io/badge/Deploy%20to-Cloudflare%20Workers-orange?style=for-the-badge&logo=cloudflare)](https://github.com/your-username/sub-hub/actions)

## 🚀 快速开始

### 一键部署（推荐）

1. Fork 此仓库到您的 GitHub 账户
2. 在 Cloudflare Dashboard 中：
   - 创建名为 "sub-hub" 的 D1 数据库
   - 获取您的 Account ID 和 API Token
3. 在 GitHub 仓库设置中配置 Secrets：
   - `CLOUDFLARE_API_TOKEN`: 您的 Cloudflare API Token
   - `CLOUDFLARE_ACCOUNT_ID`: 您的 Cloudflare Account ID
4. 推送代码到 main/master 分支，GitHub Action 将自动部署

### 本地开发

```bash
# 克隆项目
git clone https://github.com/your-username/sub-hub.git
cd sub-hub

# 安装依赖
npm install

# 本地测试（需要先配置wrangler）
npm run dev

# 部署到生产环境
npm run deploy
```

### Wrangler 配置

在本地开发前，需要配置 wrangler：

```bash
# 登录 Cloudflare
npx wrangler login

# 创建 D1 数据库（如果尚未创建）
npx wrangler d1 create sub-hub

# 初始化数据库（在 wrangler CLI 中执行）
npx wrangler d1 execute sub-hub --file=./schema.sql
```

## 功能特点

- 🚀 支持多种代理协议
  - SS（Shadowsocks）
  - VMess
  - Trojan
  - VLESS（除 Surge 外）
  - SOCKS5
  - Snell（仅 Surge）
  - WireGuard

- 💼 订阅管理
  - 创建多个独立订阅
  - 自定义订阅路径
  - 支持批量导入节点
  - 节点拖拽排序

- 🔄 多种订阅格式
  - 原始格式（适用于大多数客户端）
  - Base64 编码格式（/v2ray 路径）
  - Surge 配置格式（/surge 路径）

- 🔒 安全特性
  - 管理面板登录认证
  - 会话管理
  - 安全的 Cookie 设置

- 🎨 现代化界面
  - 响应式设计
  - 直观的操作界面
  - 支持移动设备

## 📋 部署教程

### 1. 创建项目

1. 创建名为 "sub-hub" 新的 Workers 项目

2. 创建名为 "sub-hub" 的 D1 数据库

3. 将 D1 数据库与 Cloudflare Workers 绑定
   - 变量名称 = "DB"
   - 数据库名称 = "sub-hub"

### 2. 初始化数据库

创建 `schema.sql` 文件并执行：

```sql
-- 数据库初始化
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  name TEXT NOT NULL, 
  path TEXT NOT NULL UNIQUE, 
  sub_order INTEGER DEFAULT 0, 
  updated_at INTEGER, 
  converter_backend TEXT DEFAULT 'sub.xeton.dev'
);

CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  subscription_id INTEGER NOT NULL, 
  name TEXT NOT NULL, 
  original_link TEXT NOT NULL, 
  node_order INTEGER NOT NULL DEFAULT 0, 
  enabled INTEGER DEFAULT 1, 
  FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY, 
  username TEXT NOT NULL, 
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_path ON subscriptions(path);
CREATE INDEX IF NOT EXISTS idx_nodes_subscription_order ON nodes(subscription_id, node_order);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
```

### 3. 配置环境变量

在 Cloudflare Dashboard 中设置以下环境变量：

- `ADMIN_PATH`: 管理面板路径（默认：admin）
- `ADMIN_USERNAME`: 管理员用户名（默认：admin）
- `ADMIN_PASSWORD`: 管理员密码（默认：pass）

### 4. 部署代码

#### 方法一：GitHub Action（推荐）
- 配置好 Secrets 后，推送代码即可自动部署

#### 方法二：手动部署
```bash
npm install
npm run deploy
```

### 5. 访问系统

1. 访问管理面板：
   ```
   https://你的域名/ADMIN_PATH
   ```

2. 订阅地址格式：
   - 原始格式：`https://你的域名/订阅路径`
   - Base64 格式：`https://你的域名/订阅路径/v2ray`
   - Surge 格式：`https://你的域名/订阅路径/surge`

## 🔧 使用说明

### 创建订阅

1. 登录管理面板
2. 点击"添加订阅"按钮
3. 输入订阅名称和路径（路径只能包含小写字母、数字和连字符）
4. 点击"创建"按钮

### 管理节点

1. 在订阅列表中找到目标订阅
2. 点击"添加节点"按钮添加新节点
3. 支持以下格式：
   - 单个节点链接
   - 多个节点链接（每行一个）
   - Base64 编码的节点列表

### 节点排序

1. 点击"节点列表"按钮查看节点
2. 拖拽节点行可以调整顺序
3. 顺序会自动保存

### 批量操作

1. 点击"批量删除"按钮进入批量模式
2. 勾选要删除的节点
3. 点击"确认删除"执行删除操作

## 🧪 本地测试

### 开发环境设置

1. 安装依赖：`npm install`
2. 配置 wrangler：`npx wrangler login`
3. 启动开发服务器：`npm run dev`
4. 访问 `http://localhost:8787` 进行测试

### 测试数据库

```bash
# 在本地开发时使用临时数据库
npx wrangler d1 execute sub-hub --local --file=./schema.sql

# 或者直接执行SQL语句
npx wrangler d1 execute sub-hub --local --command="SELECT * FROM subscriptions"
```

## 📁 项目结构

```
sub-hub/
├── .github/
│   └── workflows/
│       └── deploy.yml          # GitHub Action 工作流
├── worker.js                   # 主程序文件
├── package.json               # 项目配置
├── wrangler.toml              # Cloudflare 配置
└── README.md                  # 项目说明
```

## ⚠️ 注意事项

1. 首次部署后请立即修改默认的管理员密码
2. 定期备份数据库内容
3. 妥善保管管理面板地址和登录信息
4. 建议使用强密码提高安全性
5. GitHub Action 需要正确配置 Secrets 才能正常工作

## 🔄 更新部署

当有代码更新时：

- 如果使用 GitHub Action：推送代码到 main/master 分支即可自动部署
- 如果手动部署：运行 `npm run deploy`

## 🛠️ 技术栈

- Cloudflare Workers
- Cloudflare D1 (SQLite)
- HTML5 + CSS3
- JavaScript (ES6+)
- Bootstrap 5
- Font Awesome
- SortableJS
- GitHub Actions
- Wrangler CLI

## 📄 许可证

MIT License