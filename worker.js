// 通用的路径验证和节点名称提取函数
function validateSubscriptionPath(path) {
  return /^[a-z0-9-]{5,50}$/.test(path);
}

// 节点类型常量定义
const NODE_TYPES = {
  SS: 'ss://',
  VMESS: 'vmess://',
  TROJAN: 'trojan://',
  VLESS: 'vless://',
  SOCKS: 'socks://',
  HYSTERIA2: 'hysteria2://',
  TUIC: 'tuic://',
  SNELL: 'snell,'
};

function extractNodeName(nodeLink) {
  if (!nodeLink) return '未命名节点';
  
  // 处理snell节点
  if(nodeLink.includes(NODE_TYPES.SNELL)) {
    const name = nodeLink.split('=')[0].trim();
    return name || '未命名节点';
  }
  
  // 处理 VMess 链接
  if (nodeLink.toLowerCase().startsWith(NODE_TYPES.VMESS)) {
    try {
      const config = JSON.parse(safeBase64Decode(nodeLink.substring(8)));
      if (config.ps) {
        return safeUtf8Decode(config.ps);
      }
    } catch {}
    return '未命名节点';
  }

  // 处理其他使用哈希标记名称的链接类型
  const hashIndex = nodeLink.indexOf('#');
  if (hashIndex !== -1) {
    try {
      return decodeURIComponent(nodeLink.substring(hashIndex + 1));
    } catch {
      return nodeLink.substring(hashIndex + 1) || '未命名节点';
    }
  }
  return '未命名节点';
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    if (url.search && !pathname.startsWith('/admin')) {
      return new Response('Not Found', { status: 404 });
    }

    const adminPath = env.ADMIN_PATH || 'admin';
    const adminUsername = env.ADMIN_USERNAME || 'admin';
    const adminPassword = env.ADMIN_PASSWORD || 'password';
    
    // 处理登录页面请求
    if (pathname === `/${adminPath}/login`) {
      if (method === "GET") {
        return serveLoginPage(adminPath);
      } else if (method === "POST") {
        return handleLogin(request, env, adminUsername, adminPassword, adminPath);
      }
    }
    
    // 处理登出请求
    if (pathname === `/${adminPath}/logout`) {
      return handleLogout(request, env, adminPath);
    }
    
    // 处理管理面板请求
    if (pathname === `/${adminPath}`) {
      const isAuthenticated = await verifySession(request, env);
      if (!isAuthenticated) {
        return Response.redirect(`${url.origin}/${adminPath}/login`, 302);
      }
      return serveAdminPanel(env, adminPath);
    }
    
    // 处理API请求
    if (pathname.startsWith(`/${adminPath}/api/`)) {
      const isAuthenticated = await verifySession(request, env);
      if (!isAuthenticated) {
        return new Response(JSON.stringify({
          success: false,
          message: '未授权访问'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 处理节点管理API请求
      const nodeApiMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)/nodes(?:/([^/]+|reorder|batch|batch-delete))?$`));
      if (nodeApiMatch) {
        const subscriptionPath = nodeApiMatch[1];
        const nodeId = nodeApiMatch[2];
        
        try {
          if (nodeId === 'batch' && method === 'POST') {
            return handleBatchCreateNodes(request, env, subscriptionPath);
          }
          
          if (nodeId === 'batch-delete' && method === 'POST') {
            return handleBatchDeleteNodes(request, env, subscriptionPath);
          }
          
          if (nodeId === 'reorder' && method === 'POST') {
            const { orders } = await request.json();
            
            if (!Array.isArray(orders) || orders.length === 0) {
              return new Response(JSON.stringify({
                success: false,
                message: '无效的排序数据'
              }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
              });
            }
            
            const { results: subResults } = await env.DB.prepare(
              "SELECT id FROM subscriptions WHERE path = ?"
            ).bind(subscriptionPath).all();
            
            if (!subResults?.length) {
              return new Response(JSON.stringify({
                success: false,
                message: '订阅不存在'
              }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' }
              });
            }
            
            const subscriptionId = subResults[0].id;
            const statements = [];
            
            for (const { id, order } of orders) {
              statements.push(env.DB.prepare(
                "UPDATE nodes SET node_order = ? WHERE id = ? AND subscription_id = ?"
              ).bind(order, id, subscriptionId));
            }
            
            await env.DB.batch(statements);
            
            return new Response(JSON.stringify({
              success: true,
              message: '节点顺序已更新'
            }), {
              headers: { 'Content-Type': 'application/json' }
            });
          }
          
          if (!nodeId && method === 'GET') {
            return handleGetNodes(env, subscriptionPath);
          }
          
          if (!nodeId && method === 'POST') {
            return handleCreateNode(request, env, subscriptionPath);
          }
          
          if (nodeId && nodeId !== 'reorder' && nodeId !== 'batch' && nodeId !== 'batch-delete' && method === 'PUT') {
            return handleUpdateNode(request, env, subscriptionPath, nodeId);
          }
          
          if (nodeId && nodeId !== 'reorder' && nodeId !== 'batch' && nodeId !== 'batch-delete' && method === 'DELETE') {
            return handleDeleteNode(env, subscriptionPath, nodeId);
          }
          
          if (nodeId && nodeId !== 'reorder' && nodeId !== 'batch' && nodeId !== 'batch-delete' && method === 'PATCH') {
            return handleToggleNode(env, subscriptionPath, nodeId, request);
          }
          
          return new Response(JSON.stringify({
            success: false,
            message: 'Method Not Allowed'
          }), {
            status: 405,
            headers: { 'Content-Type': 'application/json' }
          });
          
        } catch (error) {
          console.error('API请求处理失败:', error);
          return new Response(JSON.stringify({
            success: false,
            message: error.message || '服务器内部错误'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      }
      
      // 处理订阅管理API请求
      if (pathname.startsWith(`/${adminPath}/api/subscriptions`)) {
        const getOneMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)$`));
        if (getOneMatch && method === 'GET') {
          return handleGetSubscription(env, getOneMatch[1]);
        }
      
        if (pathname === `/${adminPath}/api/subscriptions` && method === 'GET') {
          return handleGetSubscriptions(env);
        }
      
        if (pathname === `/${adminPath}/api/subscriptions` && method === 'POST') {
          try {
            const { name, path } = await request.json();
            
            if (!name || !validateSubscriptionPath(path)) {
              return createErrorResponse('无效的参数', 400);
            }
            
            const { results } = await env.DB.prepare(
              "SELECT COUNT(*) as count FROM subscriptions WHERE path = ?"
            ).bind(path).all();
            
            if (results[0].count > 0) {
              return createErrorResponse('该路径已被使用', 400);
            }
            
            const result = await env.DB.prepare(
              "INSERT INTO subscriptions (name, path) VALUES (?, ?)"
            ).bind(name, path).run();

            if (!result.success) {
              throw new Error('创建订阅失败');
            }

            return createSuccessResponse(null, '订阅创建成功');
          } catch (error) {
            console.error('创建订阅失败:', error);
            return createErrorResponse('创建订阅失败: ' + error.message);
          }
        }
        
        const updateMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)$`));
        if (updateMatch && method === 'PUT') {
          const data = await request.json();
          return handleUpdateSubscriptionInfo(env, updateMatch[1], data);
        }
      
        const deleteMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)$`));
        if (deleteMatch && method === 'DELETE') {
          return handleDeleteSubscription(env, deleteMatch[1]);
        }

        return new Response(JSON.stringify({
          success: false,
          message: 'Method Not Allowed'
        }), {
          status: 405,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return new Response(JSON.stringify({
        success: false,
        message: 'Not Found'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 处理订阅请求
    if (pathname.startsWith('/')) {
      const pathParts = pathname.split('/').filter(Boolean);
      if (pathParts.length > 2) {
        return new Response('Not Found', { status: 404 });
      }
      
      if (pathParts.length === 2 && !['surge', 'v2ray', 'clash'].includes(pathParts[1])) {
        return new Response('Not Found', { status: 404 });
      }

      try {
        let basePath = pathname;
        if (pathname.endsWith('/surge')) {
          basePath = pathname.slice(1, -6);
        } else if (pathname.endsWith('/v2ray')) {
          basePath = pathname.slice(1, -6);
        } else if (pathname.endsWith('/clash')) {
          basePath = pathname.slice(1, -6);
        } else {
          basePath = pathname.slice(1);
        }
        
        const { results } = await env.DB.prepare(
          "SELECT * FROM subscriptions WHERE path = ?"
        ).bind(basePath).all();
        
        const subscription = results[0];
        
        if (subscription) {
          const content = await generateSubscriptionContent(env, basePath);
          
          if (pathname.endsWith('/surge')) {
            const surgeContent = convertToSurge(content);
            return new Response(surgeContent, {
              headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            });
          } else if (pathname.endsWith('/v2ray')) {
            const filteredContent = filterSnellNodes(content);
            const base64Content = safeBase64Encode(filteredContent);
            return new Response(base64Content, {
              headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            });
          } else if (pathname.endsWith('/clash')) {
            const clashContent = convertToClash(content);
            return new Response(clashContent, {
              headers: { 'Content-Type': 'text/yaml; charset=utf-8' },
            });
          }
          
          const filteredContent = filterSnellNodes(content);
          return new Response(filteredContent, {
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
          });
        }
      } catch (error) {
        console.error('处理订阅请求失败:', error);
        return new Response('Internal Server Error', { status: 500 });
      }
      
      return new Response('Not Found', { status: 404 });
    }
    
    return new Response('Not Found', { status: 404 });
  },
};

// 批量创建节点处理函数
async function handleBatchCreateNodes(request, env, subscriptionPath) {
  try {
    const { nodes } = await request.json();
    
    if (!Array.isArray(nodes) || nodes.length === 0) {
      return createErrorResponse('无效的节点数据', 400);
    }
    
    const { results: subResults } = await env.DB.prepare(
      "SELECT id FROM subscriptions WHERE path = ?"
    ).bind(subscriptionPath).all();
    
    if (!subResults?.length) {
      return createErrorResponse('订阅不存在', 404);
    }
    
    const subscriptionId = subResults[0].id;
    const statements = [];
    const timestamp = Date.now();
    
    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i];
      let originalLink = node.content.trim();
      
      try {
        const decodedContent = safeBase64Decode(originalLink);
        if (Object.values(NODE_TYPES).some(prefix => 
          decodedContent.startsWith(prefix) && prefix !== NODE_TYPES.SNELL)) {
          originalLink = decodedContent.trim();
        }
      } catch (e) {}
      
      const lowerContent = originalLink.toLowerCase();
      const isSnell = lowerContent.includes('=') && lowerContent.includes('snell,');
      if (!['ss://', 'vmess://', 'trojan://', 'vless://', 'socks://', 'hysteria2://', 'tuic://'].some(prefix => lowerContent.startsWith(prefix)) && !isSnell) {
        continue;
      }
      
      const nodeName = node.name || extractNodeName(originalLink);
      const nodeOrder = node.order !== undefined ? node.order : (timestamp + i);
      
      statements.push(
        env.DB.prepare(
          "INSERT INTO nodes (subscription_id, name, original_link, node_order, enabled) VALUES (?, ?, ?, ?, 1)"
        ).bind(subscriptionId, nodeName, originalLink, nodeOrder)
      );
    }
    
    if (statements.length === 0) {
      return createErrorResponse('没有有效的节点可以添加', 400);
    }
    
    await env.DB.batch(statements);
    
    return createSuccessResponse({ count: statements.length }, `成功添加 ${statements.length} 个节点`);
  } catch (error) {
    console.error('批量创建节点失败:', error);
    return createErrorResponse('批量创建节点失败: ' + error.message);
  }
}

// 批量删除节点处理函数
async function handleBatchDeleteNodes(request, env, subscriptionPath) {
  try {
    const { nodeIds } = await request.json();
    
    if (!Array.isArray(nodeIds) || nodeIds.length === 0) {
      return createErrorResponse('无效的节点ID列表', 400);
    }
    
    const { results: subResults } = await env.DB.prepare(
      "SELECT id FROM subscriptions WHERE path = ?"
    ).bind(subscriptionPath).all();
    
    if (!subResults?.length) {
      return createErrorResponse('订阅不存在', 404);
    }
    
    const subscriptionId = subResults[0].id;
    const placeholders = nodeIds.map(() => '?').join(',');
    
    const result = await env.DB.prepare(
      `DELETE FROM nodes WHERE id IN (${placeholders}) AND subscription_id = ?`
    ).bind(...nodeIds, subscriptionId).run();
    
    return createSuccessResponse({ count: result.changes || nodeIds.length }, `成功删除节点`);
  } catch (error) {
    console.error('批量删除节点失败:', error);
    return createErrorResponse('批量删除节点失败: ' + error.message);
  }
}

// 获取单个订阅的处理函数
async function handleGetSubscription(env, path) {
  try {
    const { results } = await env.DB.prepare(
      "SELECT * FROM subscriptions WHERE path = ?"
    ).bind(path).all();
    
    if (!results || results.length === 0) {
      return createErrorResponse('订阅不存在', 404);
    }
    
    return createSuccessResponse(results[0]);
  } catch (error) {
    console.error('获取订阅内容失败:', error);
    return createErrorResponse('获取订阅内容失败: ' + error.message);
  }
}

// SVG 图标定义
const SVG_ICONS = {
  cube: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>`,
  user: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>`,
  lock: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`,
  login: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path><polyline points="10 17 15 12 10 7"></polyline><line x1="15" y1="12" x2="3" y2="12"></line></svg>`,
  logout: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>`,
  plus: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>`,
  list: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg>`,
  server: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>`,
  edit: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>`,
  copy: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`,
  trash: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`,
  arrowUp: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>`,
  arrowDown: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>`,
  chevronsUp: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="17 11 12 6 7 11"></polyline><polyline points="17 18 12 13 7 18"></polyline></svg>`,
  chevronsDown: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="7 13 12 18 17 13"></polyline><polyline points="7 6 12 11 17 6"></polyline></svg>`,
  check: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
  x: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`,
  checkSquare: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 11 12 14 22 4"></polyline><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>`,
  toggleOn: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="5" width="22" height="14" rx="7" ry="7"></rect><circle cx="16" cy="12" r="3"></circle></svg>`,
  toggleOff: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="5" width="22" height="14" rx="7" ry="7"></rect><circle cx="8" cy="12" r="3"></circle></svg>`,
  tasks: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l3 3L22 4"></path><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>`,
  grip: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="12" r="1"></circle><circle cx="9" cy="5" r="1"></circle><circle cx="9" cy="19" r="1"></circle><circle cx="15" cy="12" r="1"></circle><circle cx="15" cy="5" r="1"></circle><circle cx="15" cy="19" r="1"></circle></svg>`,
  terminal: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>`,
  info: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`,
  alertTriangle: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`,
  alertCircle: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`,
  loader: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="spin"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>`,
  swap: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 3l4 4-4 4"></path><path d="M20 7H4"></path><path d="M8 21l-4-4 4-4"></path><path d="M4 17h16"></path></svg>`,
  externalLink: `<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>`
};

// 提供登录页面HTML
function serveLoginPage(adminPath) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sub-Hub // Login</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-body: #050505;
      --bg-card: #121212;
      --bg-input: #0a0a0a;
      --border-color: #27272a;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --text-main: #e4e4e7;
      --text-sub: #a1a1aa;
      --text-dim: #71717a;
      --success: #22c55e;
      --danger: #ef4444;
      --warning: #f59e0b;
      --radius: 10px;
      --font-ui: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-code: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: var(--font-ui);
      background: var(--bg-body);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      color: var(--text-main);
    }

    .login-container {
      width: 100%;
      max-width: 380px;
    }

    .login-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      overflow: hidden;
    }

    .login-header {
      padding: 2rem 2rem 1.5rem;
      text-align: center;
      border-bottom: 1px solid var(--border-color);
    }

    .login-logo {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 56px;
      height: 56px;
      background: linear-gradient(135deg, var(--primary) 0%, #8b5cf6 100%);
      border-radius: 12px;
      margin-bottom: 1rem;
      color: white;
    }

    .login-logo svg {
      width: 28px;
      height: 28px;
    }

    .login-title {
      font-size: 1.25rem;
      font-weight: 600;
      color: var(--text-main);
      margin-bottom: 0.25rem;
      font-family: var(--font-code);
    }

    .login-subtitle {
      font-size: 0.75rem;
      color: var(--text-dim);
      font-family: var(--font-code);
    }

    .login-form {
      padding: 1.5rem 2rem 2rem;
    }

    .form-group {
      margin-bottom: 1rem;
    }

    .form-label {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.75rem;
      font-weight: 500;
      color: var(--text-sub);
      margin-bottom: 0.5rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .form-label svg {
      opacity: 0.7;
    }

    .form-input {
      width: 100%;
      padding: 0.75rem 1rem;
      background: var(--bg-input);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      color: var(--text-main);
      font-size: 0.875rem;
      font-family: var(--font-code);
      transition: border-color 0.2s, box-shadow 0.2s;
    }

    .form-input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
    }

    .form-input::placeholder {
      color: var(--text-dim);
    }

    .btn-login {
      width: 100%;
      padding: 0.75rem 1.5rem;
      background: var(--primary);
      border: none;
      border-radius: 6px;
      color: white;
      font-size: 0.875rem;
      font-weight: 500;
      font-family: var(--font-ui);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      transition: background-color 0.2s, transform 0.1s;
      margin-top: 1.5rem;
    }

    .btn-login:hover {
      background: var(--primary-hover);
    }

    .btn-login:active {
      transform: scale(0.98);
    }

    .alert {
      display: none;
      padding: 0.75rem 1rem;
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.2);
      border-radius: 6px;
      margin-bottom: 1rem;
      font-size: 0.8rem;
      color: var(--danger);
      font-family: var(--font-code);
    }

    .alert.show {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .terminal-prompt {
      color: var(--text-dim);
      font-family: var(--font-code);
      font-size: 0.7rem;
      text-align: center;
      margin-top: 1.5rem;
    }

    .terminal-prompt span {
      color: var(--success);
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="login-header">
        <div class="login-logo">
          ${SVG_ICONS.cube}
        </div>
        <h1 class="login-title">Sub-Hub</h1>
        <p class="login-subtitle">// authentication required</p>
      </div>
      
      <form class="login-form" id="loginForm">
        <div class="alert" id="loginAlert">
          ${SVG_ICONS.alertCircle}
          <span id="alertMessage">认证失败</span>
        </div>
        
        <div class="form-group">
          <label class="form-label">
            ${SVG_ICONS.user}
            用户名
          </label>
          <input type="text" class="form-input" id="username" name="username" placeholder="输入用户名" required autocomplete="username">
        </div>
        
        <div class="form-group">
          <label class="form-label">
            ${SVG_ICONS.lock}
            密码
          </label>
          <input type="password" class="form-input" id="password" name="password" placeholder="输入密码" required autocomplete="current-password">
        </div>
        
        <button type="submit" class="btn-login">
          ${SVG_ICONS.login}
          <span>登录系统</span>
        </button>
      </form>
    </div>
    
    <p class="terminal-prompt">
      <span>$</span> secure connection established_
    </p>
  </div>
  
  <script>
    document.getElementById('loginForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const alert = document.getElementById('loginAlert');
      const alertMessage = document.getElementById('alertMessage');
      
      try {
        const response = await fetch('/${adminPath}/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
        });
        
        const data = await response.json();
        
        if (data.success) {
          window.location.href = data.redirect;
        } else {
          alertMessage.textContent = data.message || '认证失败';
          alert.classList.add('show');
        }
      } catch (error) {
        alertMessage.textContent = '网络错误，请重试';
        alert.classList.add('show');
      }
    });
  </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// 验证会话
async function verifySession(request, env) {
  const sessionId = getSessionFromCookie(request);
  if (!sessionId) return false;
  
  const now = Date.now();
  const { results } = await env.DB.prepare(`
    UPDATE sessions 
    SET expires_at = ? 
    WHERE session_id = ? AND expires_at > ?
    RETURNING *
  `).bind(now + 24 * 60 * 60 * 1000, sessionId, now).all();
  
  return results.length > 0;
}

// 从Cookie中获取会话ID
function getSessionFromCookie(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const sessionCookie = cookieHeader.split(';')
    .find(cookie => cookie.trim().startsWith('session='));
  return sessionCookie ? sessionCookie.trim().substring(8) : null;
}

// 生成安全的会话令牌
async function generateSecureSessionToken(username, env) {
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now),
    env.DB.prepare("DELETE FROM sessions WHERE username = ?").bind(username)
  ]);

  const sessionId = crypto.randomUUID();
  const expiresAt = now + 24 * 60 * 60 * 1000;
  
  await env.DB.prepare(`
    INSERT INTO sessions (session_id, username, expires_at) 
    VALUES (?, ?, ?)
  `).bind(sessionId, username, expiresAt).run();

  return sessionId;
}

// 处理登录请求
async function handleLogin(request, env, adminUsername, adminPassword, adminPath) {
  const { username, password } = await request.json();
  
  if (!username || !password || username !== adminUsername || password !== adminPassword) {
    return new Response(JSON.stringify({
      success: false,
      message: '用户名或密码错误'
    }), {
      headers: { 'Content-Type': 'application/json' },
      status: 401
    });
  }

  const sessionId = await generateSecureSessionToken(username, env);
  const headers = new Headers({
    'Content-Type': 'application/json',
    'Set-Cookie': `session=${sessionId}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Secure`
  });
  
  return new Response(JSON.stringify({
    success: true,
    message: '登录成功',
    redirect: `/${adminPath}`
  }), { headers });
}

// 处理登出请求
async function handleLogout(request, env, adminPath) {
  const sessionId = getSessionFromCookie(request);
  if (sessionId) {
    await env.DB.prepare("DELETE FROM sessions WHERE session_id = ?").bind(sessionId).run();
  }
  
  const headers = new Headers({
    'Set-Cookie': `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure`
  });
  
  return Response.redirect(`${new URL(request.url).origin}/${adminPath}/login`, 302);
}

// 管理面板HTML生成函数
function serveAdminPanel(env, adminPath) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sub-Hub // Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js"></script>
  <style>
    :root {
      --bg-body: #050505;
      --bg-card: #121212;
      --bg-input: #0a0a0a;
      --bg-hover: #1a1a1a;
      --border-color: #27272a;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --text-main: #e4e4e7;
      --text-sub: #a1a1aa;
      --text-dim: #71717a;
      --success: #22c55e;
      --danger: #ef4444;
      --warning: #f59e0b;
      --info: #3b82f6;
      --radius: 10px;
      --radius-sm: 6px;
      --font-ui: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-code: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    /* 滚动条样式 */
    ::-webkit-scrollbar {
      width: 8px;
      height: 8px;
    }

    ::-webkit-scrollbar-track {
      background: var(--bg-body);
    }

    ::-webkit-scrollbar-thumb {
      background: #3f3f46;
      border-radius: 4px;
    }

    ::-webkit-scrollbar-thumb:hover {
      background: #52525b;
    }

    body {
      font-family: var(--font-ui);
      background: var(--bg-body);
      color: var(--text-main);
      min-height: 100vh;
      font-size: 13px;
      line-height: 1.5;
    }

    /* 导航栏 */
    .navbar {
      background: var(--bg-card);
      border-bottom: 1px solid var(--border-color);
      padding: 0 1.5rem;
      height: 56px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .navbar-brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-family: var(--font-code);
      font-weight: 600;
      font-size: 1rem;
      color: var(--text-main);
      text-decoration: none;
    }

    .navbar-brand .logo {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      background: linear-gradient(135deg, var(--primary) 0%, #8b5cf6 100%);
      border-radius: 8px;
      color: white;
    }

    .navbar-brand .logo svg {
      width: 18px;
      height: 18px;
    }

    .btn-logout {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 0.75rem;
      background: transparent;
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      color: var(--text-sub);
      font-size: 0.75rem;
      font-family: var(--font-ui);
      cursor: pointer;
      transition: all 0.2s;
      text-decoration: none;
    }

    .btn-logout:hover {
      background: var(--bg-hover);
      color: var(--danger);
      border-color: var(--danger);
    }

    /* 容器 */
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 1.5rem;
    }

    /* 页面头部 */
    .page-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.5rem;
    }

    .page-title {
      font-size: 0.75rem;
      font-weight: 500;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      font-family: var(--font-code);
    }

    /* 按钮基础样式 */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.375rem;
      padding: 0.5rem 0.875rem;
      height: 32px;
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      color: var(--text-main);
      font-size: 0.75rem;
      font-weight: 500;
      font-family: var(--font-ui);
      cursor: pointer;
      transition: all 0.15s;
      white-space: nowrap;
    }

    .btn:hover {
      background: var(--bg-hover);
    }

    .btn-primary {
      background: var(--primary);
      border-color: var(--primary);
      color: white;
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      border-color: var(--primary-hover);
    }

    .btn-success {
      background: var(--success);
      border-color: var(--success);
      color: white;
    }

    .btn-success:hover {
      background: #16a34a;
      border-color: #16a34a;
    }

    .btn-danger {
      background: transparent;
      border-color: var(--danger);
      color: var(--danger);
    }

    .btn-danger:hover {
      background: var(--danger);
      color: white;
    }

    .btn-warning {
      background: var(--warning);
      border-color: var(--warning);
      color: #000;
    }

    .btn-warning:hover {
      background: #d97706;
      border-color: #d97706;
    }

    .btn-info {
      background: var(--info);
      border-color: var(--info);
      color: white;
    }

    .btn-info:hover {
      background: #2563eb;
      border-color: #2563eb;
    }

    .btn-sm {
      height: 26px;
      padding: 0 0.5rem;
      font-size: 0.7rem;
    }

    .btn-icon {
      width: 26px;
      height: 26px;
      padding: 0;
    }

    .btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    /* 订阅卡片 */
    .subscription-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      margin-bottom: 1rem;
      overflow: hidden;
    }

    .subscription-header {
      padding: 1rem 1.25rem;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 1rem;
    }

    .subscription-info {
      flex: 1;
      min-width: 0;
    }

    .subscription-title-row {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
    }

    .subscription-name {
      font-size: 1rem;
      font-weight: 600;
      color: var(--text-main);
    }

    .node-count {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
      padding: 0.125rem 0.5rem;
      background: var(--bg-input);
      border-radius: 999px;
      font-size: 0.7rem;
      font-family: var(--font-code);
      color: var(--text-sub);
    }

    .subscription-links {
      display: flex;
      flex-direction: column;
      gap: 0.375rem;
    }

    .link-row {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.75rem;
    }

    .link-label {
      color: var(--text-dim);
      font-family: var(--font-code);
      min-width: 70px;
    }

    .link-url {
      color: var(--primary);
      font-family: var(--font-code);
      text-decoration: none;
      max-width: 300px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .link-url:hover {
      text-decoration: underline;
    }

    .btn-copy-link {
      opacity: 0.6;
      transition: opacity 0.2s;
    }

    .btn-copy-link:hover {
      opacity: 1;
    }

    .subscription-actions {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

.subscription-header {
  position: relative;
}

.subscription-title-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 0.5rem;
}

.btn-edit-sub {
  margin-left: 0.5rem;
  flex-shrink: 0;
}


    /* 节点列表区域 */
    .node-list-area {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.3s ease-out;
      border-top: 1px solid transparent;
    }

    .node-list-area.expanded {
      max-height: none;
      border-top-color: var(--border-color);
    }

    .node-list-content {
      padding: 1rem 1.25rem;
    }

    /* 节点表格 */
.node-table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}


    .node-table th {
      text-align: left;
      padding: 0.5rem 0.75rem;
      font-size: 0.7rem;
      font-weight: 500;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border-color);
      font-family: var(--font-code);
    }

    .node-row {
      border-bottom: 1px solid var(--border-color);
      transition: background-color 0.15s;
    }

    .node-row:last-child {
      border-bottom: none;
    }

    .node-row:hover {
      background: var(--bg-hover);
    }

    .node-row td {
      padding: 0.625rem 0.75rem;
      vertical-align: middle;
    }

    .node-row.disabled {
      opacity: 0.5;
    }

    .node-row.disabled .node-name,
    .node-row.disabled .node-link {
      text-decoration: line-through;
    }

    .node-cell-name {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .node-checkbox {
      width: 14px;
      height: 14px;
      cursor: pointer;
      accent-color: var(--primary);
      display: none;
    }

    .batch-mode .node-checkbox {
      display: inline-block;
    }

    .drag-handle {
      cursor: grab;
      color: var(--text-dim);
      opacity: 0.5;
      transition: opacity 0.2s;
      display: flex;
      align-items: center;
    }

    .drag-handle:hover {
      opacity: 1;
    }

.node-name {
  display: block;
  font-family: var(--font-code);
  font-size: 0.8rem;
  color: var(--text-main);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.node-link {
  display: block;
  font-family: var(--font-code);
  font-size: 0.75rem;
  color: var(--text-sub);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}


    .node-actions {
      display: flex;
      align-items: center;
      gap: 0.25rem;
      justify-content: flex-end;
    }

    /* 批量操作栏 */
    .batch-actions-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.75rem;
      background: var(--bg-input);
      border-radius: var(--radius-sm);
      margin-bottom: 1rem;
    }

    .batch-actions-left {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .batch-actions-right {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    /* 拖拽样式 */
    .sortable-ghost {
      opacity: 0.4;
      background: var(--primary) !important;
    }

    .sortable-drag {
      background: var(--bg-card);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }

    .sortable-chosen {
      background: var(--bg-hover);
    }

    /* 模态框 */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(4px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      opacity: 0;
      visibility: hidden;
      transition: opacity 0.2s, visibility 0.2s;
      padding: 1rem;
    }

    .modal-overlay.show {
      opacity: 1;
      visibility: visible;
    }

    .modal {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      width: 100%;
      max-width: 480px;
      max-height: 90vh;
      overflow: hidden;
      transform: scale(0.95);
      transition: transform 0.2s;
    }

    .modal-overlay.show .modal {
      transform: scale(1);
    }

    .modal-lg {
      max-width: 640px;
    }

    .modal-header {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .modal-title {
      font-size: 0.875rem;
      font-weight: 600;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .modal-title svg {
      color: var(--primary);
    }

    .modal-close {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 28px;
      height: 28px;
      background: transparent;
      border: none;
      border-radius: var(--radius-sm);
      color: var(--text-sub);
      cursor: pointer;
      transition: all 0.15s;
    }

    .modal-close:hover {
      background: var(--bg-hover);
      color: var(--text-main);
    }

    .modal-body {
      padding: 1.25rem;
      overflow-y: auto;
      max-height: 60vh;
    }

    .modal-footer {
      padding: 1rem 1.25rem;
      border-top: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 0.5rem;
    }

    .modal-footer-split {
      justify-content: space-between;
    }

    /* 表单 */
    .form-group {
      margin-bottom: 1rem;
    }

    .form-group:last-child {
      margin-bottom: 0;
    }

    .form-label {
      display: block;
      font-size: 0.75rem;
      font-weight: 500;
      color: var(--text-sub);
      margin-bottom: 0.5rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .form-label .required {
      color: var(--danger);
    }

    .form-input {
      width: 100%;
      padding: 0.625rem 0.875rem;
      background: var(--bg-input);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      color: var(--text-main);
      font-size: 0.8125rem;
      font-family: var(--font-code);
      transition: border-color 0.2s, box-shadow 0.2s;
    }

    .form-input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);
    }

    .form-input::placeholder {
      color: var(--text-dim);
    }

    .form-hint {
      font-size: 0.7rem;
      color: var(--text-dim);
      margin-top: 0.375rem;
      font-family: var(--font-code);
    }

    .form-error {
      font-size: 0.7rem;
      color: var(--danger);
      margin-top: 0.375rem;
      display: none;
    }

    .form-error.show {
      display: block;
    }

    textarea.form-input {
      min-height: 200px;
      resize: vertical;
      line-height: 1.6;
    }

    /* Toast */
    .toast-container {
      position: fixed;
      top: 1rem;
      right: 1rem;
      z-index: 2000;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .toast {
      display: flex;
      align-items: center;
      gap: 0.625rem;
      padding: 0.75rem 1rem;
      background: rgba(18, 18, 18, 0.95);
      backdrop-filter: blur(8px);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      font-size: 0.8rem;
      font-family: var(--font-code);
      color: var(--text-main);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      transform: translateX(120%);
      transition: transform 0.3s ease;
      max-width: 360px;
    }

    .toast.show {
      transform: translateX(0);
    }

    .toast-icon {
      flex-shrink: 0;
    }

    .toast-success { border-left: 3px solid var(--success); }
    .toast-success .toast-icon { color: var(--success); }

    .toast-danger { border-left: 3px solid var(--danger); }
    .toast-danger .toast-icon { color: var(--danger); }

    .toast-warning { border-left: 3px solid var(--warning); }
    .toast-warning .toast-icon { color: var(--warning); }

    .toast-info { border-left: 3px solid var(--info); }
    .toast-info .toast-icon { color: var(--info); }

    .toast-prefix {
      color: var(--text-dim);
    }

    /* 空状态 */
    .empty-state {
      text-align: center;
      padding: 2rem;
      color: var(--text-dim);
      font-family: var(--font-code);
      font-size: 0.8rem;
    }

    /* 加载动画 */
    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .spin {
      animation: spin 1s linear infinite;
    }

    /* 响应式 */
    @media (max-width: 768px) {
      .container {
        padding: 1rem;
      }

      .page-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 1rem;
      }

      .subscription-header {
        flex-direction: column;
      }

      .subscription-actions {
        flex-direction: row;
        width: 100%;
      }

      .subscription-actions .btn {
        flex: 1;
      }

      .subscription-links {
        width: 100%;
      }

      .link-url {
        max-width: 180px;
      }

      .node-table th:nth-child(2),
      .node-row td:nth-child(2) {
        display: none;
      }

      .node-name {
        max-width: 150px;
      }

      .node-actions {
        flex-wrap: nowrap;
      }

      .batch-actions-bar {
        flex-direction: column;
        gap: 0.75rem;
      }

      .batch-actions-left,
      .batch-actions-right {
        width: 100%;
        flex-wrap: wrap;
      }

      .batch-actions-right .btn {
        flex: 1;
      }

      .toast-container {
        left: 1rem;
        right: 1rem;
      }

      .toast {
        max-width: 100%;
      }

      .modal {
        max-height: 85vh;
      }

      .modal-body {
        max-height: 50vh;
      }
    }
  </style>
</head>
<body>
  <nav class="navbar">
    <a class="navbar-brand" href="#">
      <span class="logo">${SVG_ICONS.cube}</span>
      <span>Sub-Hub</span>
    </a>
    <a href="/${adminPath}/logout" class="btn-logout">
      ${SVG_ICONS.logout}
      <span>退出</span>
    </a>
  </nav>

  <div class="container">
    <div class="page-header">
      <div class="page-title">${SVG_ICONS.terminal} // subscription_manager</div>
      <button class="btn btn-primary" onclick="showModal('addSubscriptionModal')">
        ${SVG_ICONS.plus}
        <span>添加订阅</span>
      </button>
    </div>

    <div id="subscriptionList"></div>
  </div>

  <!-- 添加订阅模态框 -->
  <div class="modal-overlay" id="addSubscriptionModal">
    <div class="modal">
      <div class="modal-header">
        <h3 class="modal-title">${SVG_ICONS.plus} 添加订阅</h3>
        <button class="modal-close" onclick="hideModal('addSubscriptionModal')">${SVG_ICONS.x}</button>
      </div>
      <div class="modal-body">
        <form id="addSubscriptionForm" onsubmit="return false;">
          <div class="form-group">
            <label class="form-label">订阅名称 <span class="required">*</span></label>
            <input type="text" class="form-input" name="name" required placeholder="例如: My Subscription">
          </div>
          <div class="form-group">
            <label class="form-label">订阅路径 <span class="required">*</span></label>
            <input type="text" class="form-input" name="path" required pattern="^[a-z0-9-]+$" minlength="5" maxlength="50" placeholder="例如: my-sub-path">
            <div class="form-hint">仅支持小写字母、数字和连字符，5-50个字符</div>
            <div class="form-error" id="addSubPathError"></div>
          </div>
        </form>
      </div>
      <div class="modal-footer">
        <button class="btn" onclick="hideModal('addSubscriptionModal')">取消</button>
        <button class="btn btn-primary" onclick="createSubscription()">创建</button>
      </div>
    </div>
  </div>

  <!-- 编辑订阅模态框 -->
  <div class="modal-overlay" id="editSubscriptionModal">
    <div class="modal">
      <div class="modal-header">
        <h3 class="modal-title">${SVG_ICONS.edit} 编辑订阅</h3>
        <button class="modal-close" onclick="hideModal('editSubscriptionModal')">${SVG_ICONS.x}</button>
      </div>
      <div class="modal-body">
        <form id="editSubscriptionForm" onsubmit="return false;">
          <input type="hidden" name="originalPath">
          <div class="form-group">
            <label class="form-label">订阅名称 <span class="required">*</span></label>
            <input type="text" class="form-input" name="name" required>
          </div>
          <div class="form-group">
            <label class="form-label">订阅路径 <span class="required">*</span></label>
            <input type="text" class="form-input" name="path" required pattern="^[a-z0-9-]+$" minlength="5" maxlength="50">
            <div class="form-hint">仅支持小写字母、数字和连字符，5-50个字符</div>
            <div class="form-error" id="editSubPathError"></div>
          </div>
        </form>
      </div>
      <div class="modal-footer modal-footer-split">
        <button class="btn btn-danger" onclick="confirmDeleteSubscription()">
          ${SVG_ICONS.trash} 删除订阅
        </button>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn" onclick="hideModal('editSubscriptionModal')">取消</button>
          <button class="btn btn-primary" onclick="updateSubscriptionInfo()">保存</button>
        </div>
      </div>
    </div>
  </div>

  <!-- 添加节点模态框 -->
  <div class="modal-overlay" id="addNodeModal">
    <div class="modal modal-lg">
      <div class="modal-header">
        <h3 class="modal-title">${SVG_ICONS.plus} 添加节点</h3>
        <button class="modal-close" onclick="hideModal('addNodeModal')">${SVG_ICONS.x}</button>
      </div>
      <div class="modal-body">
        <form id="addNodeForm" onsubmit="return false;">
          <input type="hidden" name="subscriptionPath">
          <div class="form-group">
            <label class="form-label">节点内容 <span class="required">*</span></label>
            <textarea class="form-input" name="content" required placeholder="支持的格式：
ss://...
vmess://...
trojan://...
vless://...
socks://...
hysteria2://...
tuic://...
snell格式（仅Surge）
Base64编码格式

可一次添加多个节点，每行一个"></textarea>
          </div>
        </form>
      </div>
      <div class="modal-footer">
        <button class="btn" onclick="hideModal('addNodeModal')">取消</button>
        <button class="btn btn-primary" onclick="createNode()">${SVG_ICONS.plus} 添加</button>
      </div>
    </div>
  </div>

  <!-- 编辑节点模态框 -->
  <div class="modal-overlay" id="editNodeModal">
    <div class="modal modal-lg">
      <div class="modal-header">
        <h3 class="modal-title">${SVG_ICONS.edit} 编辑节点</h3>
        <button class="modal-close" onclick="hideModal('editNodeModal')">${SVG_ICONS.x}</button>
      </div>
      <div class="modal-body">
        <form id="editNodeForm" onsubmit="return false;">
          <input type="hidden" name="subscriptionPath">
          <input type="hidden" name="nodeId">
          <div class="form-group">
            <label class="form-label">节点内容 <span class="required">*</span></label>
            <textarea class="form-input" name="content" required></textarea>
          </div>
        </form>
      </div>
      <div class="modal-footer">
        <button class="btn" onclick="hideModal('editNodeModal')">取消</button>
        <button class="btn btn-primary" onclick="updateNode()">保存</button>
      </div>
    </div>
  </div>

  <!-- Toast容器 -->
  <div class="toast-container" id="toastContainer"></div>

  <script>
    const adminPath = '${adminPath}';
    const SVG_ICONS = {
      cube: \`${SVG_ICONS.cube}\`,
      server: \`${SVG_ICONS.server}\`,
      edit: \`${SVG_ICONS.edit}\`,
      copy: \`${SVG_ICONS.copy}\`,
      trash: \`${SVG_ICONS.trash}\`,
      plus: \`${SVG_ICONS.plus}\`,
      list: \`${SVG_ICONS.list}\`,
      arrowUp: \`${SVG_ICONS.arrowUp}\`,
      arrowDown: \`${SVG_ICONS.arrowDown}\`,
      chevronsUp: \`${SVG_ICONS.chevronsUp}\`,
      chevronsDown: \`${SVG_ICONS.chevronsDown}\`,
      check: \`${SVG_ICONS.check}\`,
      x: \`${SVG_ICONS.x}\`,
      checkSquare: \`${SVG_ICONS.checkSquare}\`,
      toggleOn: \`${SVG_ICONS.toggleOn}\`,
      toggleOff: \`${SVG_ICONS.toggleOff}\`,
      tasks: \`${SVG_ICONS.tasks}\`,
      grip: \`${SVG_ICONS.grip}\`,
      terminal: \`${SVG_ICONS.terminal}\`,
      info: \`${SVG_ICONS.info}\`,
      alertTriangle: \`${SVG_ICONS.alertTriangle}\`,
      alertCircle: \`${SVG_ICONS.alertCircle}\`,
      loader: \`${SVG_ICONS.loader}\`,
      externalLink: \`${SVG_ICONS.externalLink}\`
    };

    // 节点类型常量
    const NODE_TYPES_FRONTEND = {
      SS: 'ss://',
      VMESS: 'vmess://',
      TROJAN: 'trojan://',
      VLESS: 'vless://',
      SOCKS: 'socks://',
      HYSTERIA2: 'hysteria2://',
      TUIC: 'tuic://',
      SNELL: 'snell,'
    };

    // 检测是否为移动设备
    function isMobileDevice() {
      return window.innerWidth <= 768 || 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    }

    // Toast 提示
    function showToast(message, type = 'success') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = \`toast toast-\${type}\`;
      
      const icons = {
        success: SVG_ICONS.check,
        danger: SVG_ICONS.alertCircle,
        warning: SVG_ICONS.alertTriangle,
        info: SVG_ICONS.info
      };
      
      const prefixes = {
        success: '[OK]',
        danger: '[ERR]',
        warning: '[WARN]',
        info: '[INFO]'
      };
      
      toast.innerHTML = \`
        <span class="toast-icon">\${icons[type] || icons.info}</span>
        <span class="toast-prefix">\${prefixes[type] || prefixes.info}</span>
        <span>\${message}</span>
      \`;
      
      container.appendChild(toast);
      
      requestAnimationFrame(() => {
        toast.classList.add('show');
      });
      
      setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
      }, 3000);
    }

    // 模态框控制
    function showModal(id) {
      document.getElementById(id).classList.add('show');
      document.body.style.overflow = 'hidden';
    }

    function hideModal(id) {
      document.getElementById(id).classList.remove('show');
      document.body.style.overflow = '';
    }

    // 复制到剪贴板
    function copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => {
        showToast('已复制到剪贴板', 'success');
      }).catch(() => {
        showToast('复制失败', 'danger');
      });
    }

    // 生成订阅转换器链接
    function generateSubConverterUrl(path) {
      const origin = window.location.origin;
      const v2rayUrl = origin + '/' + path + '/v2ray';
      const encodedUrl = encodeURIComponent(v2rayUrl);
      return 'https://sub.xeton.dev/sub?target=clash&url=' + encodedUrl + '&insert=false&config=https%3A%2F%2Fraw.githubusercontent.com%2Fszkane%2FClashRuleSet%2Fmain%2FClash%2Fkclash.ini&emoji=true&list=false&xudp=false&udp=true&tfo=false&expand=false&scv=false&fdn=false&new_name=true';
    }

    // 复制订阅链接
    function copySubscriptionLink(path, type) {
      const origin = window.location.origin;
      let url = '';
      switch(type) {
        case 1: url = origin + '/' + path; break;
        case 2: url = origin + '/' + path + '/v2ray'; break;
        case 3: url = origin + '/' + path + '/surge'; break;
        case 4: url = origin + '/' + path + '/clash'; break;
        case 5: url = generateSubConverterUrl(path); break;
      }
      copyToClipboard(url);
    }

    // 路径验证
    function validateSubscriptionPathFrontend(path) {
      return /^[a-z0-9-]{5,50}$/.test(path);
    }

    // 安全的Base64解码
    function safeBase64DecodeFrontend(str) {
      try {
        const decoded = atob(str);
        const bytes = [];
        for (let i = 0; i < decoded.length; i++) {
          bytes.push(decoded.charCodeAt(i));
        }
        if (typeof TextDecoder !== 'undefined') {
          const decoder = new TextDecoder('utf-8');
          return decoder.decode(new Uint8Array(bytes));
        } else {
          let utf8String = '';
          for (let i = 0; i < bytes.length; i++) {
            utf8String += String.fromCharCode(bytes[i]);
          }
          return decodeURIComponent(escape(utf8String));
        }
      } catch (e) {
        try {
          return atob(str);
        } catch (e2) {
          return str;
        }
      }
    }

    // 安全的UTF-8解码
    function safeUtf8DecodeFrontend(str) {
      if (!str) return str;
      try {
        return decodeURIComponent(escape(str));
      } catch (e1) {
        try {
          return decodeURIComponent(str);
        } catch (e2) {
          return str;
        }
      }
    }

    // 提取节点名称
    function extractNodeNameFrontend(nodeLink) {
      if (!nodeLink) return '未命名节点';
      
      if(nodeLink.includes(NODE_TYPES_FRONTEND.SNELL)) {
        const name = nodeLink.split('=')[0].trim();
        return name || '未命名节点';
      }
      
      if (nodeLink.toLowerCase().startsWith(NODE_TYPES_FRONTEND.VMESS)) {
        try {
          const config = JSON.parse(safeBase64DecodeFrontend(nodeLink.substring(8)));
          if (config.ps) {
            return safeUtf8DecodeFrontend(config.ps);
          }
        } catch {}
        return '未命名节点';
      }

      const hashIndex = nodeLink.indexOf('#');
      if (hashIndex !== -1) {
        try {
          return decodeURIComponent(nodeLink.substring(hashIndex + 1));
        } catch {
          return nodeLink.substring(hashIndex + 1) || '未命名节点';
        }
      }
      return '未命名节点';
    }

    // 检查是否是有效的节点链接
    function isValidNodeLink(link) {
      const lowerLink = link.toLowerCase();
      if(lowerLink.includes('=') && lowerLink.includes('snell,')) {
        const parts = link.split('=')[1]?.trim().split(',');
        return parts && parts.length >= 4 && parts[0].trim() === 'snell';
      }
      return Object.values(NODE_TYPES_FRONTEND).some(prefix => lowerLink.startsWith(prefix));
    }

    // 加载订阅列表
    async function loadSubscriptions() {
      try {
        const response = await fetch('/' + adminPath + '/api/subscriptions');
        if (!response.ok) throw new Error('加载失败');
        const result = await response.json();
        
        if (!result.success) throw new Error(result.message || '加载失败');
        
        const subscriptions = result.data || [];
        const listElement = document.getElementById('subscriptionList');
        
        if (subscriptions.length === 0) {
          listElement.innerHTML = '<div class="empty-state">// no subscriptions found</div>';
          return;
        }
        
        listElement.innerHTML = subscriptions.map(sub => {
          const subConverterUrl = generateSubConverterUrl(sub.path);
          return \`
            <div class="subscription-card" data-path="\${sub.path}">
<div class="subscription-header">
  <div class="subscription-info">
    <div class="subscription-title-row">
      <span class="subscription-name">\${sub.name}</span>
      <span class="node-count">\${SVG_ICONS.server} \${sub.nodeCount}</span>
      <button class="btn btn-sm btn-icon btn-edit-sub" onclick="showEditSubscriptionModal('\${sub.path}', '\${sub.name}')" title="编辑">
        \${SVG_ICONS.edit}
      </button>
    </div>

                  <div class="subscription-links">
                    <div class="link-row">
                      <span class="link-label">Default:</span>
                      <a href="/\${sub.path}" target="_blank" class="link-url">/\${sub.path}</a>
                      <button class="btn btn-sm btn-icon btn-copy-link" onclick="copySubscriptionLink('\${sub.path}', 1)" title="复制">\${SVG_ICONS.copy}</button>
                    </div>
                    <div class="link-row">
                      <span class="link-label">V2Ray:</span>
                      <a href="/\${sub.path}/v2ray" target="_blank" class="link-url">/\${sub.path}/v2ray</a>
                      <button class="btn btn-sm btn-icon btn-copy-link" onclick="copySubscriptionLink('\${sub.path}', 2)" title="复制">\${SVG_ICONS.copy}</button>
                    </div>
                    <div class="link-row">
                      <span class="link-label">Surge:</span>
                      <a href="/\${sub.path}/surge" target="_blank" class="link-url">/\${sub.path}/surge</a>
                      <button class="btn btn-sm btn-icon btn-copy-link" onclick="copySubscriptionLink('\${sub.path}', 3)" title="复制">\${SVG_ICONS.copy}</button>
                    </div>
                    <div class="link-row">
                      <span class="link-label">Clash:</span>
                      <a href="/\${sub.path}/clash" target="_blank" class="link-url">/\${sub.path}/clash</a>
                      <button class="btn btn-sm btn-icon btn-copy-link" onclick="copySubscriptionLink('\${sub.path}', 4)" title="复制">\${SVG_ICONS.copy}</button>
                    </div>
                    <div class="link-row">
                      <span class="link-label">Convert:</span>
                      <a href="\${subConverterUrl}" target="_blank" class="link-url">订阅转换器 \${SVG_ICONS.externalLink}</a>
                      <button class="btn btn-sm btn-icon btn-copy-link" onclick="copySubscriptionLink('\${sub.path}', 5)" title="复制">\${SVG_ICONS.copy}</button>
                    </div>
                  </div>
                </div>
                <div class="subscription-actions">
                  <button class="btn btn-success" onclick="showAddNodeModal('\${sub.path}')">
                    \${SVG_ICONS.plus} 添加节点
                  </button>
                  <button class="btn btn-primary" onclick="toggleNodeList('\${sub.path}')">
                    \${SVG_ICONS.list} 节点列表
                  </button>
                </div>
              </div>
              <div class="node-list-area" id="node-list-\${sub.path}">
                <div class="node-list-content">
                  <div id="batch-bar-\${sub.path}" style="display: none;"></div>
                  <table class="node-table">
  <thead>
    <tr>
      <th style="width: 30%;">节点名称</th>
      <th style="width: 40%;">节点链接</th>
      <th style="width: 30%; text-align: right;">操作</th>
    </tr>
  </thead>

                    <tbody id="node-tbody-\${sub.path}"></tbody>
                  </table>
                  <div id="node-footer-\${sub.path}" style="margin-top: 1rem; display: flex; justify-content: flex-end;">
                    <button class="btn" onclick="enterBatchMode('\${sub.path}')">
                      \${SVG_ICONS.tasks} 批量操作
                    </button>
                  </div>
                </div>
              </div>
            </div>
          \`;
        }).join('');
      } catch (error) {
        showToast('加载订阅列表失败: ' + error.message, 'danger');
      }
    }

    // 切换节点列表显示
    async function toggleNodeList(subscriptionPath) {
      const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
      const isExpanded = nodeListArea.classList.contains('expanded');
      
      if (isExpanded) {
        nodeListArea.classList.remove('expanded');
      } else {
        nodeListArea.classList.add('expanded');
        await loadNodeList(subscriptionPath);
      }
    }

    // 加载节点列表
    async function loadNodeList(subscriptionPath) {
      const tbody = document.getElementById('node-tbody-' + subscriptionPath);
      tbody.innerHTML = \`<tr><td colspan="3" class="empty-state">\${SVG_ICONS.loader} loading...</td></tr>\`;
      
      try {
        const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes');
        if (!response.ok) throw new Error('加载失败');
        
        const result = await response.json();
        if (!result.success) throw new Error(result.message || '加载失败');
        
        const nodes = result.data || [];
        
        if (nodes.length === 0) {
          tbody.innerHTML = '<tr><td colspan="3" class="empty-state">// no nodes</td></tr>';
          return;
        }
        
        tbody.innerHTML = nodes.map((node, index) => {
          const isEnabled = node.enabled === 1;
          const isFirst = index === 0;
          const isLast = index === nodes.length - 1;
          const escapedLink = node.original_link.replace(/&/g, '&amp;').replace(/'/g, "\\'").replace(/"/g, '\\"');
          
          return \`
            <tr class="node-row \${!isEnabled ? 'disabled' : ''}" data-id="\${node.id}" data-order="\${node.node_order}">
              <td>
                <div class="node-cell-name">
                  <input type="checkbox" class="node-checkbox" value="\${node.id}">
                  <span class="drag-handle" title="拖拽排序">\${SVG_ICONS.grip}</span>
                  <span class="node-name" title="\${node.name}">\${node.name}</span>
                </div>
              </td>
              <td>
                <span class="node-link" title="\${node.original_link}">\${node.original_link}</span>
              </td>
              <td>
                <div class="node-actions">
                  <button class="btn btn-sm btn-icon btn-info" onclick="moveNodeToTop('\${subscriptionPath}', \${node.id})" title="移至顶部" \${isFirst ? 'disabled' : ''}>\${SVG_ICONS.chevronsUp}</button>
                  <button class="btn btn-sm btn-icon btn-info" onclick="moveNodeUp('\${subscriptionPath}', \${node.id})" title="上移" \${isFirst ? 'disabled' : ''}>\${SVG_ICONS.arrowUp}</button>
                  <button class="btn btn-sm btn-icon btn-info" onclick="moveNodeDown('\${subscriptionPath}', \${node.id})" title="下移" \${isLast ? 'disabled' : ''}>\${SVG_ICONS.arrowDown}</button>
                  <button class="btn btn-sm btn-icon btn-info" onclick="moveNodeToBottom('\${subscriptionPath}', \${node.id})" title="移至底部" \${isLast ? 'disabled' : ''}>\${SVG_ICONS.chevronsDown}</button>
                  <button class="btn btn-sm btn-icon" onclick="showEditNodeModal('\${subscriptionPath}', '\${node.id}', '\${escapedLink}')" title="编辑">\${SVG_ICONS.edit}</button>
                  <button class="btn btn-sm btn-icon" onclick="copyToClipboard('\${escapedLink}')" title="复制">\${SVG_ICONS.copy}</button>
                  <button class="btn btn-sm btn-icon btn-danger" onclick="deleteNode('\${subscriptionPath}', \${node.id})" title="删除">\${SVG_ICONS.trash}</button>
                </div>
              </td>
            </tr>
          \`;
        }).join('');

        // 初始化拖拽排序（PC和移动端都启用）
        initializeSortable(tbody, subscriptionPath);
        
      } catch (error) {
        tbody.innerHTML = \`<tr><td colspan="3" class="empty-state" style="color: var(--danger);">\${SVG_ICONS.alertCircle} \${error.message}</td></tr>\`;
      }
    }

    // 初始化拖拽排序
    function initializeSortable(tbody, subscriptionPath) {
      if (tbody.sortableInstance) {
        tbody.sortableInstance.destroy();
      }
      
      tbody.sortableInstance = new Sortable(tbody, {
        animation: 150,
        handle: '.drag-handle',
        ghostClass: 'sortable-ghost',
        chosenClass: 'sortable-chosen',
        dragClass: 'sortable-drag',
        forceFallback: true, // 移动端更好的兼容性
        fallbackTolerance: 3,
        touchStartThreshold: 3,
        delay: isMobileDevice() ? 150 : 0, // 移动端添加延迟防止误触
        delayOnTouchOnly: true,
        onEnd: async function(evt) {
          try {
            const rows = Array.from(tbody.querySelectorAll('.node-row'));
            const newOrders = rows.map((row, index) => ({
              id: parseInt(row.dataset.id),
              order: index
            }));
            await updateNodeOrder(subscriptionPath, newOrders);
            showToast('节点顺序已更新', 'success');
          } catch (error) {
            showToast('更新排序失败: ' + error.message, 'danger');
            await loadNodeList(subscriptionPath);
          }
        }
      });
    }

    // 更新节点顺序
    async function updateNodeOrder(subscriptionPath, orders) {
      const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/reorder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ orders })
      });
      
      const result = await response.json();
      if (!result.success) throw new Error(result.message || '保存排序失败');
      
      await loadNodeList(subscriptionPath);
      return result;
    }

    // 节点移动功能
    async function moveNodeUp(subscriptionPath, nodeId) {
      const tbody = document.getElementById('node-tbody-' + subscriptionPath);
      const rows = Array.from(tbody.querySelectorAll('.node-row'));
      const currentIndex = rows.findIndex(row => parseInt(row.dataset.id) === nodeId);
      
      if (currentIndex <= 0) return;
      
      const newOrders = rows.map((row, index) => {
        const id = parseInt(row.dataset.id);
        if (index === currentIndex - 1) return { id, order: currentIndex };
        if (index === currentIndex) return { id, order: currentIndex - 1 };
        return { id, order: index };
      });
      
      try {
        await updateNodeOrder(subscriptionPath, newOrders);
        showToast('节点已上移', 'success');
      } catch (error) {
        showToast('上移失败: ' + error.message, 'danger');
      }
    }

    async function moveNodeDown(subscriptionPath, nodeId) {
      const tbody = document.getElementById('node-tbody-' + subscriptionPath);
      const rows = Array.from(tbody.querySelectorAll('.node-row'));
      const currentIndex = rows.findIndex(row => parseInt(row.dataset.id) === nodeId);
      
      if (currentIndex >= rows.length - 1) return;
      
      const newOrders = rows.map((row, index) => {
        const id = parseInt(row.dataset.id);
        if (index === currentIndex) return { id, order: currentIndex + 1 };
        if (index === currentIndex + 1) return { id, order: currentIndex };
        return { id, order: index };
      });
      
      try {
        await updateNodeOrder(subscriptionPath, newOrders);
        showToast('节点已下移', 'success');
      } catch (error) {
        showToast('下移失败: ' + error.message, 'danger');
      }
    }

    async function moveNodeToTop(subscriptionPath, nodeId) {
      const tbody = document.getElementById('node-tbody-' + subscriptionPath);
      const rows = Array.from(tbody.querySelectorAll('.node-row'));
      const currentIndex = rows.findIndex(row => parseInt(row.dataset.id) === nodeId);
      
      if (currentIndex <= 0) return;
      
      const newOrders = rows.map((row, index) => {
        const id = parseInt(row.dataset.id);
        if (id === nodeId) return { id, order: 0 };
        if (index < currentIndex) return { id, order: index + 1 };
        return { id, order: index };
      });
      
      try {
        await updateNodeOrder(subscriptionPath, newOrders);
        showToast('节点已移至顶部', 'success');
      } catch (error) {
        showToast('移动失败: ' + error.message, 'danger');
      }
    }

    async function moveNodeToBottom(subscriptionPath, nodeId) {
      const tbody = document.getElementById('node-tbody-' + subscriptionPath);
      const rows = Array.from(tbody.querySelectorAll('.node-row'));
      const currentIndex = rows.findIndex(row => parseInt(row.dataset.id) === nodeId);
      
      if (currentIndex >= rows.length - 1) return;
      
      const lastIndex = rows.length - 1;
      const newOrders = rows.map((row, index) => {
        const id = parseInt(row.dataset.id);
        if (id === nodeId) return { id, order: lastIndex };
        if (index > currentIndex) return { id, order: index - 1 };
        return { id, order: index };
      });
      
      try {
        await updateNodeOrder(subscriptionPath, newOrders);
        showToast('节点已移至底部', 'success');
      } catch (error) {
        showToast('移动失败: ' + error.message, 'danger');
      }
    }

    // 批量操作模式
    function enterBatchMode(subscriptionPath) {
      const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
      const batchBar = document.getElementById('batch-bar-' + subscriptionPath);
      const footer = document.getElementById('node-footer-' + subscriptionPath);
      
      nodeListArea.querySelector('.node-list-content').classList.add('batch-mode');
      footer.style.display = 'none';
      
      batchBar.style.display = 'block';
      batchBar.innerHTML = \`
        <div class="batch-actions-bar">
          <div class="batch-actions-left">
            <button class="btn btn-sm" onclick="toggleSelectAll('\${subscriptionPath}')" id="select-all-btn-\${subscriptionPath}">
              \${SVG_ICONS.checkSquare} 全选
            </button>
<button class="btn btn-sm" onclick="invertSelection('\${subscriptionPath}')">
  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 3l4 4-4 4"></path><path d="M20 7H4"></path><path d="M8 21l-4-4 4-4"></path><path d="M4 17h16"></path></svg> 反选
</button>

			
          </div>
          <div class="batch-actions-right">
            <button class="btn btn-sm btn-success" onclick="executeBatchStatusChange('\${subscriptionPath}', true)">
              \${SVG_ICONS.toggleOn} 启用
            </button>
            <button class="btn btn-sm btn-warning" onclick="executeBatchStatusChange('\${subscriptionPath}', false)">
              \${SVG_ICONS.toggleOff} 禁用
            </button>
            <button class="btn btn-sm btn-danger" onclick="executeBatchDelete('\${subscriptionPath}')">
              \${SVG_ICONS.trash} 删除
            </button>
            <button class="btn btn-sm" onclick="exitBatchMode('\${subscriptionPath}')">
              \${SVG_ICONS.x} 取消
            </button>
          </div>
        </div>
      \`;
      
      showToast('已进入批量操作模式', 'info');
    }

    function exitBatchMode(subscriptionPath) {
      const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
      const batchBar = document.getElementById('batch-bar-' + subscriptionPath);
      const footer = document.getElementById('node-footer-' + subscriptionPath);
      
      nodeListArea.querySelector('.node-list-content').classList.remove('batch-mode');
      batchBar.style.display = 'none';
      footer.style.display = 'flex';
      
      // 取消所有选择
      nodeListArea.querySelectorAll('.node-checkbox').forEach(cb => cb.checked = false);
    }

function toggleSelectAll(subscriptionPath) {
  const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
  const checkboxes = nodeListArea.querySelectorAll('.node-checkbox');
  const btn = document.getElementById('select-all-btn-' + subscriptionPath);
  
  const checkedCount = nodeListArea.querySelectorAll('.node-checkbox:checked').length;
  const isAllSelected = checkedCount === checkboxes.length && checkboxes.length > 0;
  
  checkboxes.forEach(cb => cb.checked = !isAllSelected);
  btn.innerHTML = isAllSelected ? \`\${SVG_ICONS.checkSquare} 全选\` : \`\${SVG_ICONS.x} 取消全选\`;
}

// 反选
function invertSelection(subscriptionPath) {
  const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
  const checkboxes = nodeListArea.querySelectorAll('.node-checkbox');
  checkboxes.forEach(cb => cb.checked = !cb.checked);
}


    async function executeBatchDelete(subscriptionPath) {
      const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
      const checkedNodes = nodeListArea.querySelectorAll('.node-checkbox:checked');
      
      if (checkedNodes.length === 0) {
        showToast('请先选择节点', 'warning');
        return;
      }
      
      if (!confirm(\`确定删除选中的 \${checkedNodes.length} 个节点？\`)) return;
      
      const nodeIds = Array.from(checkedNodes).map(cb => parseInt(cb.value));
      
      try {
        showToast('正在删除...', 'info');
        
        const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/batch-delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ nodeIds })
        });
        
        const result = await response.json();
        if (!result.success) throw new Error(result.message);
        
        showToast(\`成功删除 \${nodeIds.length} 个节点\`, 'success');
        exitBatchMode(subscriptionPath);
        await loadNodeList(subscriptionPath);
        await loadSubscriptions();
      } catch (error) {
        showToast('删除失败: ' + error.message, 'danger');
      }
    }

    async function executeBatchStatusChange(subscriptionPath, enabled) {
      const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
      const checkedNodes = nodeListArea.querySelectorAll('.node-checkbox:checked');
      
      if (checkedNodes.length === 0) {
        showToast('请先选择节点', 'warning');
        return;
      }
      
      const action = enabled ? '启用' : '禁用';
      if (!confirm(\`确定\${action}选中的 \${checkedNodes.length} 个节点？\`)) return;
      
      try {
        showToast(\`正在\${action}...\`, 'info');
        
        let successCount = 0;
        for (const cb of checkedNodes) {
          try {
            const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/' + cb.value, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ enabled })
            });
            if (response.ok) successCount++;
          } catch (e) {}
        }
        
        showToast(\`成功\${action} \${successCount} 个节点\`, 'success');
        exitBatchMode(subscriptionPath);
        await loadNodeList(subscriptionPath);
        await loadSubscriptions();
      } catch (error) {
        showToast(\`\${action}失败: \` + error.message, 'danger');
      }
    }

    // 显示添加节点模态框
    function showAddNodeModal(subscriptionPath) {
      const form = document.getElementById('addNodeForm');
      form.reset();
      form.querySelector('[name="subscriptionPath"]').value = subscriptionPath;
      showModal('addNodeModal');
    }

    // 创建节点
    async function createNode() {
      const form = document.getElementById('addNodeForm');
      const subscriptionPath = form.querySelector('[name="subscriptionPath"]').value;
      const content = form.querySelector('[name="content"]').value.trim();
      
      if (!content) {
        showToast('请输入节点内容', 'warning');
        return;
      }
      
      const lines = content.split(/\\r?\\n/);
      const validNodes = [];
      
      for (const line of lines) {
        const trimmedLine = line.trim();
        if (!trimmedLine) continue;
        
        try {
          const decodedContent = safeBase64DecodeFrontend(trimmedLine);
          const decodedLines = decodedContent.split(/\\r?\\n/);
          for (const decodedLine of decodedLines) {
            if (decodedLine.trim() && isValidNodeLink(decodedLine.trim())) {
              validNodes.push({
                name: extractNodeNameFrontend(decodedLine.trim()),
                content: decodedLine.trim()
              });
            }
          }
        } catch (e) {
          if (isValidNodeLink(trimmedLine)) {
            validNodes.push({
              name: extractNodeNameFrontend(trimmedLine),
              content: trimmedLine
            });
          }
        }
      }
      
      if (validNodes.length === 0) {
        showToast('未找到有效的节点', 'warning');
        return;
      }
      
      try {
        showToast('正在添加...', 'info');
        
        const timestamp = Date.now();
        const nodesWithOrder = validNodes.map((node, index) => ({
          name: node.name,
          content: node.content,
          order: timestamp + index
        }));
        
        const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/batch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ nodes: nodesWithOrder })
        });
        
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);
        
        showToast(\`成功添加 \${result.data?.count || validNodes.length} 个节点\`, 'success');
        hideModal('addNodeModal');
        form.reset();
        await loadSubscriptions();
        await loadNodeList(subscriptionPath);
      } catch (error) {
        showToast('添加失败: ' + error.message, 'danger');
      }
    }

    // 显示编辑节点模态框
    function showEditNodeModal(subscriptionPath, nodeId, nodeContent) {
      const form = document.getElementById('editNodeForm');
      form.querySelector('[name="subscriptionPath"]').value = subscriptionPath;
      form.querySelector('[name="nodeId"]').value = nodeId;
      form.querySelector('[name="content"]').value = nodeContent;
      form.setAttribute('data-original-content', nodeContent);
      showModal('editNodeModal');
    }

    // 更新节点
    async function updateNode() {
      const form = document.getElementById('editNodeForm');
      const subscriptionPath = form.querySelector('[name="subscriptionPath"]').value;
      const nodeId = form.querySelector('[name="nodeId"]').value;
      const content = form.querySelector('[name="content"]').value.trim();
      const originalContent = form.getAttribute('data-original-content');
      
      if (!content) {
        showToast('请输入节点内容', 'warning');
        return;
      }
      
      if (content === originalContent) {
        showToast('内容未修改', 'info');
        hideModal('editNodeModal');
        return;
      }
      
      try {
        const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/' + nodeId, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content })
        });
        
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);
        
        showToast('节点已更新', 'success');
        hideModal('editNodeModal');
        await loadSubscriptions();
        await loadNodeList(subscriptionPath);
      } catch (error) {
        showToast('更新失败: ' + error.message, 'danger');
      }
    }

    // 删除节点
    async function deleteNode(subscriptionPath, nodeId) {
      if (!confirm('确定删除此节点？')) return;
      
      try {
        const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/' + nodeId, {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' }
        });
        
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);
        
        showToast('节点已删除', 'success');
        await loadNodeList(subscriptionPath);
        await loadSubscriptions();
      } catch (error) {
        showToast('删除失败: ' + error.message, 'danger');
      }
    }

    // 创建订阅
    async function createSubscription() {
      const form = document.getElementById('addSubscriptionForm');
      const name = form.querySelector('[name="name"]').value.trim();
      const path = form.querySelector('[name="path"]').value.trim();
      const errorEl = document.getElementById('addSubPathError');
      
      if (!name) {
        showToast('请输入订阅名称', 'warning');
        return;
      }
      
      if (!validateSubscriptionPathFrontend(path)) {
        errorEl.textContent = '路径格式不正确';
        errorEl.classList.add('show');
        return;
      }
      
      errorEl.classList.remove('show');
      
      try {
        const response = await fetch('/' + adminPath + '/api/subscriptions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, path })
        });
        
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);
        
        showToast('订阅创建成功', 'success');
        hideModal('addSubscriptionModal');
        form.reset();
        await loadSubscriptions();
      } catch (error) {
        showToast('创建失败: ' + error.message, 'danger');
      }
    }

    // 显示编辑订阅模态框
    function showEditSubscriptionModal(path, name) {
      const form = document.getElementById('editSubscriptionForm');
      form.querySelector('[name="originalPath"]').value = path;
      form.querySelector('[name="name"]').value = name;
      form.querySelector('[name="path"]').value = path;
      document.getElementById('editSubPathError').classList.remove('show');
      showModal('editSubscriptionModal');
    }

    // 更新订阅信息
    async function updateSubscriptionInfo() {
      const form = document.getElementById('editSubscriptionForm');
      const originalPath = form.querySelector('[name="originalPath"]').value;
      const name = form.querySelector('[name="name"]').value.trim();
      const path = form.querySelector('[name="path"]').value.trim();
      const errorEl = document.getElementById('editSubPathError');
      
      if (!name) {
        showToast('请输入订阅名称', 'warning');
        return;
      }
      
      if (!validateSubscriptionPathFrontend(path)) {
        errorEl.textContent = '路径格式不正确';
        errorEl.classList.add('show');
        return;
      }
      
      errorEl.classList.remove('show');
      
      try {
        if (path !== originalPath) {
          const checkResponse = await fetch('/' + adminPath + '/api/subscriptions/' + path);
          if (checkResponse.ok) {
            errorEl.textContent = '该路径已被使用';
            errorEl.classList.add('show');
            return;
          }
        }
        
        const response = await fetch('/' + adminPath + '/api/subscriptions/' + originalPath, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, path, action: 'update_info' })
        });
        
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);
        
        showToast('订阅信息已更新', 'success');
        hideModal('editSubscriptionModal');
        await loadSubscriptions();
      } catch (error) {
        showToast('更新失败: ' + error.message, 'danger');
      }
    }

    // 确认删除订阅
    async function confirmDeleteSubscription() {
      const form = document.getElementById('editSubscriptionForm');
      const path = form.querySelector('[name="originalPath"]').value;
      
      if (!confirm('确定删除此订阅及其所有节点？')) return;
      
      try {
        const response = await fetch('/' + adminPath + '/api/subscriptions/' + path, {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' }
        });
        
        if (!response.ok) {
          const result = await response.json();
          throw new Error(result.message);
        }
        
        showToast('订阅已删除', 'success');
        hideModal('editSubscriptionModal');
        await loadSubscriptions();
      } catch (error) {
        showToast('删除失败: ' + error.message, 'danger');
      }
    }

    // 页面加载完成后初始化
    window.addEventListener('load', loadSubscriptions);
  </script>
</body>
</html>`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// 通用响应头
const JSON_HEADERS = { 'Content-Type': 'application/json' };

// 通用响应创建函数
function createResponse(success, message, data = null, status = success ? 200 : 500) {
  return new Response(
    JSON.stringify({
      success,
      message,
      ...(data && { data })
    }), 
    {
      headers: JSON_HEADERS,
      status
    }
  );
}

// 错误响应函数
const createErrorResponse = (message, status = 500) => 
  createResponse(false, message, null, status);

// 成功响应函数
const createSuccessResponse = (data = null, message = '操作成功') => 
  createResponse(true, message, data);

// 获取订阅列表函数
async function handleGetSubscriptions(env) {
  const { results } = await env.DB.prepare(`
    SELECT 
      s.path,
      s.name,
      COUNT(n.id) as nodeCount
    FROM subscriptions s
    LEFT JOIN nodes n ON s.id = n.subscription_id
    GROUP BY s.id
    ORDER BY s.id ASC
  `).all();
  
  const subscriptions = results.map(item => ({
    name: item.name,
    path: item.path,
    nodeCount: item.nodeCount || 0
  }));

  return createSuccessResponse(subscriptions);
}

// 获取节点列表的函数
async function handleGetNodes(env, subscriptionPath) {
  const { results } = await env.DB.prepare(`
    SELECT 
      n.id,
      n.name,
      n.original_link,
      n.node_order,
      COALESCE(n.enabled, 1) as enabled
    FROM nodes n
    JOIN subscriptions s ON n.subscription_id = s.id
    WHERE s.path = ?
    ORDER BY n.node_order ASC
  `).bind(subscriptionPath).all();
  
  return createSuccessResponse(results || []);
}

// 创建节点的函数
async function handleCreateNode(request, env, subscriptionPath) {
  const nodeData = await request.json();
  
  if (!nodeData.content) {
    return createErrorResponse('缺少节点内容', 400);
  }
  
  const { results: subResults } = await env.DB.prepare(
    "SELECT id FROM subscriptions WHERE path = ?"
  ).bind(subscriptionPath).all();
  
  if (!subResults?.length) {
    return createErrorResponse('订阅不存在', 404);
  }
  
  const subscriptionId = subResults[0].id;
  let originalLink = nodeData.content.trim();
  
  try {
    const decodedContent = safeBase64Decode(originalLink);
    if (Object.values(NODE_TYPES).some(prefix => 
      decodedContent.startsWith(prefix) && prefix !== NODE_TYPES.SNELL)) {
      originalLink = decodedContent.trim();
    }
  } catch (e) {}

  const lowerContent = originalLink.toLowerCase();
  const isSnell = lowerContent.includes('=') && lowerContent.includes('snell,');
  if (!['ss://', 'vmess://', 'trojan://', 'vless://', 'socks://', 'hysteria2://', 'tuic://'].some(prefix => lowerContent.startsWith(prefix)) && !isSnell) {
    return createErrorResponse('不支持的节点格式', 400);
  }
  
  let nodeName = extractNodeName(originalLink);
  const nodeOrder = nodeData.order;

  await env.DB.prepare(`
    INSERT INTO nodes (subscription_id, name, original_link, node_order, enabled) 
    VALUES (?, ?, ?, ?, 1)
  `).bind(subscriptionId, nodeName, originalLink, nodeOrder).run();

  return createSuccessResponse(null, '节点创建成功');
}

// 删除节点的函数
async function handleDeleteNode(env, subscriptionPath, nodeId) {
  try {
    await env.DB.prepare(`
      DELETE FROM nodes
      WHERE id = ? AND subscription_id = (
        SELECT id FROM subscriptions WHERE path = ? LIMIT 1
      )
    `).bind(nodeId, subscriptionPath).run();

    return createSuccessResponse(null, '节点已删除');
  } catch (error) {
    return createErrorResponse('删除节点失败: ' + error.message);
  }
}

// 切换节点状态的函数
async function handleToggleNode(env, subscriptionPath, nodeId, request) {
  try {
    const { enabled } = await request.json();
    
    if (typeof enabled !== 'boolean') {
      return createErrorResponse('无效的状态值', 400);
    }
    
    const result = await env.DB.prepare(`
      UPDATE nodes 
      SET enabled = ?
      WHERE id = ? AND subscription_id = (
        SELECT id FROM subscriptions WHERE path = ? LIMIT 1
      )
    `).bind(enabled ? 1 : 0, nodeId, subscriptionPath).run();

    if (result.changes === 0) {
      return createErrorResponse('节点不存在或更新失败', 404);
    }

    return createSuccessResponse(null, '节点已' + (enabled ? '启用' : '禁用'));
  } catch (error) {
    return createErrorResponse('切换节点状态失败: ' + error.message);
  }
}

// 生成订阅内容
async function generateSubscriptionContent(env, path) {
  if (!path?.trim()) return '';

  const { results } = await env.DB.prepare(`
    SELECT GROUP_CONCAT(n.original_link, CHAR(10)) as content
    FROM nodes n
    JOIN subscriptions s ON n.subscription_id = s.id
    WHERE s.path = ? AND n.original_link IS NOT NULL AND (n.enabled IS NULL OR n.enabled = 1)
    GROUP BY s.id
    ORDER BY n.node_order ASC
  `).bind(path).all();

  return results?.[0]?.content || '';
}

// 解析SIP002格式
function parseSIP002Format(ssLink) {
  try {
    const [base, name = ''] = ssLink.split('#');
    if (!base.startsWith(NODE_TYPES.SS)) return null;
    
    const prefixRemoved = base.substring(5);
    const atIndex = prefixRemoved.indexOf('@');
    if (atIndex === -1) return null;
    
    const serverPortPart = prefixRemoved.substring(atIndex + 1);
    let server, port;
    
    if (serverPortPart.startsWith('[')) {
      const closeBracketIndex = serverPortPart.indexOf(']');
      if (closeBracketIndex === -1) return null;
      
      server = serverPortPart.substring(1, closeBracketIndex);
      const portPart = serverPortPart.substring(closeBracketIndex + 1);
      port = portPart.startsWith(':') ? portPart.substring(1) : '';
    } else {
      const lastColonIndex = serverPortPart.lastIndexOf(':');
      if (lastColonIndex === -1) return null;
      
      server = serverPortPart.substring(0, lastColonIndex);
      port = serverPortPart.substring(lastColonIndex + 1);
    }
    
    if (!server || !port) return null;
    
    let method, password;
    const methodPassBase64 = prefixRemoved.substring(0, atIndex);
    try {
      [method, password] = safeBase64Decode(methodPassBase64).split(':');
    } catch {
      [method, password] = safeDecodeURIComponent(methodPassBase64).split(':');
    }
    
    if (!method || !password) return null;
    
    const nodeName = name ? decodeURIComponent(name) : '未命名节点';
    return `${nodeName} = ss, ${server}, ${port}, encrypt-method=${method}, password=${password}`;
  } catch {
    return null;
  }
}

// 解析Vmess链接为Surge格式
function parseVmessLink(vmessLink) {
  if (!vmessLink.startsWith(NODE_TYPES.VMESS)) return null;
  
  try {
    const config = JSON.parse(safeBase64Decode(vmessLink.substring(8)));
    if (!config.add || !config.port || !config.id) return null;
    
    const name = config.ps ? safeUtf8Decode(config.ps) : '未命名节点';
    const configParts = [
      `${name} = vmess`,
      config.add,
      config.port,
      `username=${config.id}`,
      'vmess-aead=true',
      `tls=${config.tls === 'tls'}`,
      `sni=${config.add}`,
      'skip-cert-verify=true',
      'tfo=false'
    ];

    if (config.tls === 'tls' && config.alpn) {
      configParts.push(`alpn=${config.alpn.replace(/,/g, ':')}`);
    }

    if (config.net === 'ws') {
      configParts.push('ws=true');
      if (config.path) configParts.push(`ws-path=${config.path}`);
      configParts.push(`ws-headers=Host:${config.host || config.add}`);
    }

    return configParts.join(', ');
  } catch {
    return null;
  }
}

// 解析Trojan链接为Surge格式
function parseTrojanLink(trojanLink) {
  if (!trojanLink.startsWith(NODE_TYPES.TROJAN)) return null;
  
  try {
    const url = new URL(trojanLink);
    if (!url.hostname || !url.port || !url.username) return null;
    
    const params = new URLSearchParams(url.search);
    const nodeName = url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点';
    
    const configParts = [
      `${nodeName} = trojan`,
      url.hostname,
      url.port,
      `password=${url.username}`,
      'tls=true',
      `sni=${url.hostname}`,
      'skip-cert-verify=true',
      'tfo=false'
    ];

    const alpn = params.get('alpn');
    if (alpn) {
      configParts.push(`alpn=${safeDecodeURIComponent(alpn).replace(/,/g, ':')}`);
    }

    if (params.get('type') === 'ws') {
      configParts.push('ws=true');
      const path = params.get('path');
      if (path) {
        configParts.push(`ws-path=${safeDecodeURIComponent(path)}`);
      }
      const host = params.get('host');
      configParts.push(`ws-headers=Host:${host ? safeDecodeURIComponent(host) : url.hostname}`);
    }

    return configParts.join(', ');
  } catch {
    return null;
  }
}

// 解析SOCKS链接为Surge格式
function parseSocksLink(socksLink) {
  if (!socksLink.startsWith(NODE_TYPES.SOCKS)) return null;
  
  try {
    const url = new URL(socksLink);
    if (!url.hostname || !url.port) return null;
    
    const nodeName = url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点';
    
    let username = '', password = '';
    
    if (url.username) {
      let decodedUsername = safeDecodeURIComponent(url.username);
      
      try {
        const decoded = safeBase64Decode(decodedUsername);
        if (decoded.includes(':')) {
          const parts = decoded.split(':');
          if (parts.length >= 2) {
            username = parts[0];
            password = parts[1];
          } else {
            username = decodedUsername;
          }
        } else {
          username = decodedUsername;
          if (url.password) {
            password = safeDecodeURIComponent(url.password);
          }
        }
      } catch (e) {
        username = decodedUsername;
        if (url.password) {
          password = safeDecodeURIComponent(url.password);
        }
      }
    }
    
    const configParts = [
      nodeName + " = socks5",
      url.hostname,
      url.port
    ];
    
    if (username) configParts.push(username);
    if (password) configParts.push(password);
    
    return configParts.join(', ');
  } catch (error) {
    return null;
  }
}

// 更新订阅信息的函数
async function handleUpdateSubscriptionInfo(env, path, data) {
  const name = data.name?.trim();
  const newPath = data.path?.trim();

  if (!name) {
    return createErrorResponse('订阅名称不能为空', 400);
  }
  
  if (!validateSubscriptionPath(newPath)) {
    return createErrorResponse('无效的订阅路径格式', 400);
  }

  try {
    if (newPath !== path) {
      const { results } = await env.DB.prepare(`
        SELECT 1 FROM subscriptions WHERE path = ? LIMIT 1
      `).bind(newPath).all();
      
      if (results.length > 0) {
        return createErrorResponse('该路径已被使用', 400);
      }
    }

    const statements = [
      env.DB.prepare(
        "UPDATE subscriptions SET name = ?, path = ? WHERE path = ?"
      ).bind(name, newPath, path),
      env.DB.prepare(
        "SELECT id, name, path FROM subscriptions WHERE path = ?"
      ).bind(newPath)
    ];

    const [updateResult, { results }] = await env.DB.batch(statements);
    
    if (!results?.[0]) {
      return createErrorResponse('更新失败：找不到订阅', 404);
    }

    return createSuccessResponse(results[0], '订阅信息已更新');
  } catch (error) {
    return createErrorResponse('更新订阅信息失败: ' + error.message);
  }
}

// 删除订阅的处理函数
async function handleDeleteSubscription(env, path) {
  const statements = [
    env.DB.prepare(
      "DELETE FROM nodes WHERE subscription_id IN (SELECT id FROM subscriptions WHERE path = ?)"
    ).bind(path),
    env.DB.prepare(
      "DELETE FROM subscriptions WHERE path = ?"
    ).bind(path)
  ];
  
  await env.DB.batch(statements);
  
  return createSuccessResponse(null, '订阅已删除');
}

// 更新节点的处理函数
async function handleUpdateNode(request, env, subscriptionPath, nodeId) {
  const nodeData = await request.json();
  
  const { results: subResults } = await env.DB.prepare(
    "SELECT id FROM subscriptions WHERE path = ?"
  ).bind(subscriptionPath).all();
  
  if (!subResults?.length) {
    return createErrorResponse('订阅不存在', 404);
  }
  
  const subscriptionId = subResults[0].id;
  let originalLink = nodeData.content.replace(/[\r\n\s]+$/, '');

  try {
    const decodedContent = safeBase64Decode(originalLink);
    if (Object.values(NODE_TYPES).some(prefix => 
      decodedContent.startsWith(prefix) && prefix !== NODE_TYPES.SNELL)) {
      originalLink = decodedContent.replace(/[\r\n\s]+$/, '');
    }
  } catch (e) {}

  const nodeName = extractNodeName(originalLink);

  await env.DB.prepare(`
    UPDATE nodes 
    SET original_link = ?, name = ? 
    WHERE id = ? AND subscription_id = ?
  `).bind(originalLink, nodeName || '未命名节点', nodeId, subscriptionId).run();

  return createSuccessResponse(null, '节点更新成功');
}

// 将订阅内容转换为surge格式
function convertToSurge(content) {
  if (!content?.trim()) return '';
  
  const nodeParserMap = new Map([
    [NODE_TYPES.SS, parseSIP002Format],
    [NODE_TYPES.VMESS, parseVmessLink],
    [NODE_TYPES.TROJAN, parseTrojanLink],
    [NODE_TYPES.SOCKS, parseSocksLink],
    [NODE_TYPES.HYSTERIA2, parseHysteria2ToSurge],
    [NODE_TYPES.TUIC, parseTuicToSurge]
  ]);
  
  return content
    .split(/\r?\n/)
    .map(line => {
      const trimmedLine = line.trim();
      if (!trimmedLine) return null;
      
      if (trimmedLine.includes(NODE_TYPES.SNELL)) {
        return formatSnellConfig(trimmedLine);
      }
      
      if (trimmedLine.toLowerCase().startsWith(NODE_TYPES.VLESS)) {
        return null;
      }
      
      for (const [prefix, parser] of nodeParserMap.entries()) {
        if (trimmedLine.startsWith(prefix)) {
          return parser(trimmedLine);
        }
      }
      
      return null;
    })
    .filter(Boolean)
    .join('\n');
}

// 格式化snell配置
function formatSnellConfig(snellConfig) {
  if (!snellConfig) return null;
  
  const parts = snellConfig.split(',').map(part => part.trim());
  return parts.join(', ');
}

// 安全的URL解码辅助函数
function safeDecodeURIComponent(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

// 安全的Base64编码辅助函数
function safeBase64Encode(str) {
  try {
    return btoa(unescape(encodeURIComponent(str)));
  } catch (e) {
    return str;
  }
}

// 安全的Base64解码辅助函数
function safeBase64Decode(str) {
  try {
    const decoded = atob(str);
    const bytes = [];
    for (let i = 0; i < decoded.length; i++) {
      bytes.push(decoded.charCodeAt(i));
    }
    if (typeof TextDecoder !== 'undefined') {
      const decoder = new TextDecoder('utf-8');
      return decoder.decode(new Uint8Array(bytes));
    } else {
      let utf8String = '';
      for (let i = 0; i < bytes.length; i++) {
        utf8String += String.fromCharCode(bytes[i]);
      }
      return decodeURIComponent(escape(utf8String));
    }
  } catch (e) {
    try {
      return atob(str);
    } catch (e2) {
      return str;
    }
  }
}

// 安全的UTF-8字符串解码函数
function safeUtf8Decode(str) {
  if (!str) return str;
  
  try {
    return decodeURIComponent(escape(str));
  } catch (e1) {
    try {
      return decodeURIComponent(str);
    } catch (e2) {
      try {
        if (typeof TextDecoder !== 'undefined') {
          const encoder = new TextEncoder();
          const decoder = new TextDecoder('utf-8');
          return decoder.decode(encoder.encode(str));
        }
      } catch (e3) {
        return str;
      }
      return str;
    }
  }
}

// 过滤掉snell节点的函数
function filterSnellNodes(content) {
  if (!content?.trim()) return '';
  
  return content
    .split(/\r?\n/)
    .filter(line => {
      const trimmedLine = line.trim();
      if (!trimmedLine) return false;
      return !trimmedLine.includes(NODE_TYPES.SNELL);
    })
    .join('\n');
}

// 将订阅内容转换为 Clash 格式
function convertToClash(content) {
  if (!content?.trim()) {
    return generateEmptyClashConfig();
  }
  
  const nodes = content
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(parseNodeToClash)
    .filter(Boolean);
  
  return generateClashConfig(nodes);
}

// 解析单个节点为 Clash 格式
function parseNodeToClash(nodeLink) {
  if (!nodeLink) return null;
  
  const lowerLink = nodeLink.toLowerCase();
  
  if (nodeLink.includes(NODE_TYPES.SNELL)) return null;
  
  if (lowerLink.startsWith(NODE_TYPES.SS)) return parseSSToClash(nodeLink);
  if (lowerLink.startsWith(NODE_TYPES.VMESS)) return parseVmessToClash(nodeLink);
  if (lowerLink.startsWith(NODE_TYPES.TROJAN)) return parseTrojanToClash(nodeLink);
  if (lowerLink.startsWith(NODE_TYPES.VLESS)) return parseVlessToClash(nodeLink);
  if (lowerLink.startsWith(NODE_TYPES.SOCKS)) return parseSocksToClash(nodeLink);
  if (lowerLink.startsWith(NODE_TYPES.HYSTERIA2)) return parseHysteria2ToClash(nodeLink);
  if (lowerLink.startsWith(NODE_TYPES.TUIC)) return parseTuicToClash(nodeLink);
  
  return null;
}

// 解析 SS 节点为 Clash 格式
function parseSSToClash(ssLink) {
  try {
    const [base, name = ''] = ssLink.split('#');
    if (!base.startsWith(NODE_TYPES.SS)) return null;
    
    const prefixRemoved = base.substring(5);
    const atIndex = prefixRemoved.indexOf('@');
    if (atIndex === -1) return null;
    
    const serverPortPart = prefixRemoved.substring(atIndex + 1);
    let server, port;
    
    if (serverPortPart.startsWith('[')) {
      const closeBracketIndex = serverPortPart.indexOf(']');
      if (closeBracketIndex === -1) return null;
      
      server = serverPortPart.substring(1, closeBracketIndex);
      const portPart = serverPortPart.substring(closeBracketIndex + 1);
      port = portPart.startsWith(':') ? portPart.substring(1) : '';
    } else {
      const lastColonIndex = serverPortPart.lastIndexOf(':');
      if (lastColonIndex === -1) return null;
      
      server = serverPortPart.substring(0, lastColonIndex);
      port = serverPortPart.substring(lastColonIndex + 1);
    }
    
    if (!server || !port) return null;
    
    let method, password;
    const methodPassBase64 = prefixRemoved.substring(0, atIndex);
    try {
      [method, password] = safeBase64Decode(methodPassBase64).split(':');
    } catch {
      [method, password] = safeDecodeURIComponent(methodPassBase64).split(':');
    }
    
    if (!method || !password) return null;
    
    return {
      name: name ? decodeURIComponent(name) : '未命名节点',
      type: 'ss',
      server: server,
      port: parseInt(port),
      cipher: method,
      password: password
    };
  } catch {
    return null;
  }
}

// 解析 VMess 节点为 Clash 格式
function parseVmessToClash(vmessLink) {
  if (!vmessLink.startsWith(NODE_TYPES.VMESS)) return null;
  
  try {
    const config = JSON.parse(safeBase64Decode(vmessLink.substring(8)));
    if (!config.add || !config.port || !config.id) return null;
    
    const node = {
      name: config.ps ? safeUtf8Decode(config.ps) : '未命名节点',
      type: 'vmess',
      server: config.add,
      port: parseInt(config.port),
      uuid: config.id,
      alterId: parseInt(config.aid) || 0,
      cipher: 'auto',
      tls: config.tls === 'tls'
    };
    
    if (config.net === 'ws') {
      node.network = 'ws';
      if (config.path) {
        node['ws-opts'] = {
          path: config.path,
          headers: {
            Host: config.host || config.add
          }
        };
      }
    } else if (config.net === 'grpc') {
      node.network = 'grpc';
      if (config.path) {
        node['grpc-opts'] = {
          'grpc-service-name': config.path
        };
      }
    }
    
    if (config.tls === 'tls') {
      node['skip-cert-verify'] = true;
      if (config.sni) {
        node.servername = config.sni;
      }
    }
    
    return node;
  } catch {
    return null;
  }
}

// 解析 Trojan 节点为 Clash 格式
function parseTrojanToClash(trojanLink) {
  if (!trojanLink.startsWith(NODE_TYPES.TROJAN)) return null;
  
  try {
    const url = new URL(trojanLink);
    if (!url.hostname || !url.port || !url.username) return null;
    
    const params = new URLSearchParams(url.search);
    const node = {
      name: url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点',
      type: 'trojan',
      server: url.hostname,
      port: parseInt(url.port),
      password: url.username,
      'skip-cert-verify': true
    };
    
    if (params.get('type') === 'ws') {
      node.network = 'ws';
      const path = params.get('path');
      const host = params.get('host');
      if (path || host) {
        node['ws-opts'] = {};
        if (path) node['ws-opts'].path = safeDecodeURIComponent(path);
        if (host) {
          node['ws-opts'].headers = { Host: safeDecodeURIComponent(host) };
        }
      }
    } else if (params.get('type') === 'grpc') {
      node.network = 'grpc';
      const serviceName = params.get('serviceName') || params.get('path');
      if (serviceName) {
        node['grpc-opts'] = {
          'grpc-service-name': safeDecodeURIComponent(serviceName)
        };
      }
    }
    
    const sni = params.get('sni');
    if (sni) {
      node.sni = safeDecodeURIComponent(sni);
    }
    
    return node;
  } catch {
    return null;
  }
}

// 解析 VLESS 节点为 Clash 格式
function parseVlessToClash(vlessLink) {
  if (!vlessLink.startsWith(NODE_TYPES.VLESS)) return null;
  
  try {
    const url = new URL(vlessLink);
    if (!url.hostname || !url.port || !url.username) return null;
    
    const params = new URLSearchParams(url.search);
    const node = {
      name: url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点',
      type: 'vless',
      server: url.hostname,
      port: parseInt(url.port),
      uuid: url.username,
      tls: params.get('security') === 'tls' || params.get('security') === 'reality',
      'client-fingerprint': 'chrome',
      tfo: false,
      'skip-cert-verify': false
    };
    
    const flow = params.get('flow');
    if (flow) {
      node.flow = flow;
    }
    
    if (params.get('security') === 'reality') {
      const publicKey = params.get('pbk');
      const shortId = params.get('sid');
      if (publicKey || shortId) {
        node['reality-opts'] = {};
        if (publicKey) node['reality-opts']['public-key'] = publicKey;
        if (shortId) node['reality-opts']['short-id'] = shortId;
      }
    }
    
    const type = params.get('type');
    if (type === 'ws') {
      node.network = 'ws';
      const path = params.get('path');
      const host = params.get('host');
      if (path || host) {
        node['ws-opts'] = {};
        if (path) node['ws-opts'].path = safeDecodeURIComponent(path);
        if (host) {
          node['ws-opts'].headers = { Host: safeDecodeURIComponent(host) };
        }
      }
    } else if (type === 'grpc') {
      node.network = 'grpc';
      const serviceName = params.get('serviceName') || params.get('path');
      if (serviceName) {
        node['grpc-opts'] = {
          'grpc-service-name': safeDecodeURIComponent(serviceName)
        };
      }
    } else {
      node.network = 'tcp';
    }
    
    const sni = params.get('sni');
    if (sni) {
      node.servername = safeDecodeURIComponent(sni);
    }
    
    return node;
  } catch {
    return null;
  }
}

// 解析 SOCKS 节点为 Clash 格式
function parseSocksToClash(socksLink) {
  if (!socksLink.startsWith(NODE_TYPES.SOCKS)) return null;
  
  try {
    const url = new URL(socksLink);
    if (!url.hostname || !url.port) return null;
    
    const node = {
      name: url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点',
      type: 'socks5',
      server: url.hostname,
      port: parseInt(url.port)
    };
    
    if (url.username) {
      let username = '', password = '';
      let decodedUsername = safeDecodeURIComponent(url.username);
      
      try {
        const decoded = safeBase64Decode(decodedUsername);
        if (decoded.includes(':')) {
          const parts = decoded.split(':');
          if (parts.length >= 2) {
            username = parts[0];
            password = parts[1];
          }
        } else {
          username = decodedUsername;
          if (url.password) {
            password = safeDecodeURIComponent(url.password);
          }
        }
      } catch (e) {
        username = decodedUsername;
        if (url.password) {
          password = safeDecodeURIComponent(url.password);
        }
      }
      
      if (username) node.username = username;
      if (password) node.password = password;
    }
    
    return node;
  } catch {
    return null;
  }
}

// 生成 Clash 配置文件
function generateClashConfig(proxies) {
  const proxyNames = proxies.map(proxy => proxy.name);
  
  const config = {
    'global-ua': 'clash',
    mode: 'rule',
    'mixed-port': 7890,
    'allow-lan': true,
    'external-controller': '0.0.0.0:9090',
    proxies: proxies.length > 0 ? proxies : [],
    'proxy-groups': [
      {
        name: '节点选择',
        type: 'select',
        proxies: ['DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png'
      },
      {
        name: '媒体服务',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Netflix.png'
      },
      {
        name: '微软服务',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Microsoft.png'
      },
      {
        name: '苹果服务',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Apple.png'
      },
      {
        name: 'CDN服务',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/OneDrive.png'
      },
      {
        name: 'AI服务',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ChatGPT.png'
      },
      {
        name: 'Telegram',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png'
      },
      {
        name: 'Speedtest',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Speedtest.png'
      },
    ],
    rules: [
      'RULE-SET,reject_non_ip,REJECT',
      'RULE-SET,reject_domainset,REJECT',
      'RULE-SET,reject_extra_domainset,REJECT',
      'RULE-SET,reject_non_ip_drop,REJECT-DROP',
      'RULE-SET,reject_non_ip_no_drop,REJECT',
      'RULE-SET,speedtest,Speedtest',
      'RULE-SET,telegram_non_ip,Telegram',
      'RULE-SET,apple_cdn,DIRECT',
      'RULE-SET,apple_cn_non_ip,DIRECT',
      'RULE-SET,microsoft_cdn_non_ip,DIRECT',
      'RULE-SET,apple_services,苹果服务',
      'RULE-SET,microsoft_non_ip,微软服务',
      'RULE-SET,download_domainset,CDN服务',
      'RULE-SET,download_non_ip,CDN服务',
      'RULE-SET,cdn_domainset,CDN服务',
      'RULE-SET,cdn_non_ip,CDN服务',
      'RULE-SET,stream_non_ip,媒体服务',
      'RULE-SET,ai_non_ip,AI服务',
      'RULE-SET,global_non_ip,节点选择',
      'RULE-SET,domestic_non_ip,DIRECT',
      'RULE-SET,direct_non_ip,DIRECT',
      'RULE-SET,lan_non_ip,DIRECT',
      'GEOSITE,CN,DIRECT',
      'RULE-SET,reject_ip,REJECT',
      'RULE-SET,telegram_ip,Telegram',
      'RULE-SET,stream_ip,媒体服务',
      'RULE-SET,lan_ip,DIRECT',
      'RULE-SET,domestic_ip,DIRECT',
      'RULE-SET,china_ip,DIRECT',
      'GEOIP,LAN,DIRECT',
      'GEOIP,CN,DIRECT',
      'MATCH,节点选择'
    ],
    'rule-providers': {
      reject_non_ip_no_drop: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/reject-no-drop.txt', path: './rule_set/sukkaw_ruleset/reject_non_ip_no_drop.txt' },
      reject_non_ip_drop: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/reject-drop.txt', path: './rule_set/sukkaw_ruleset/reject_non_ip_drop.txt' },
      reject_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/reject.txt', path: './rule_set/sukkaw_ruleset/reject_non_ip.txt' },
      reject_domainset: { type: 'http', behavior: 'domain', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/domainset/reject.txt', path: './rule_set/sukkaw_ruleset/reject_domainset.txt' },
      reject_extra_domainset: { type: 'http', behavior: 'domain', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/domainset/reject_extra.txt', path: './sukkaw_ruleset/reject_domainset_extra.txt' },
      reject_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/ip/reject.txt', path: './rule_set/sukkaw_ruleset/reject_ip.txt' },
      speedtest: { type: 'http', behavior: 'domain', interval: 43200, format: 'text', proxy: 'Speedtest', url: 'https://ruleset.skk.moe/Clash/domainset/speedtest.txt', path: './rule_set/sukkaw_ruleset/speedtest.txt' },
      cdn_domainset: { type: 'http', behavior: 'domain', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/domainset/cdn.txt', path: './rule_set/sukkaw_ruleset/cdn_domainset.txt' },
      cdn_non_ip: { type: 'http', behavior: 'domain', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/cdn.txt', path: './rule_set/sukkaw_ruleset/cdn_non_ip.txt' },
      stream_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/stream.txt', path: './rule_set/sukkaw_ruleset/stream_non_ip.txt' },
      stream_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/ip/stream.txt', path: './rule_set/sukkaw_ruleset/stream_ip.txt' },
      ai_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/ai.txt', path: './rule_set/sukkaw_ruleset/ai_non_ip.txt' },
      telegram_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/telegram.txt', path: './rule_set/sukkaw_ruleset/telegram_non_ip.txt' },
      telegram_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/ip/telegram.txt', path: './rule_set/sukkaw_ruleset/telegram_ip.txt' },
      apple_cdn: { type: 'http', behavior: 'domain', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/domainset/apple_cdn.txt', path: './rule_set/sukkaw_ruleset/apple_cdn.txt' },
      apple_services: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/apple_services.txt', path: './rule_set/sukkaw_ruleset/apple_services.txt' },
      apple_cn_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/apple_cn.txt', path: './rule_set/sukkaw_ruleset/apple_cn_non_ip.txt' },
      microsoft_cdn_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/microsoft_cdn.txt', path: './rule_set/sukkaw_ruleset/microsoft_cdn_non_ip.txt' },
      microsoft_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/microsoft.txt', path: './rule_set/sukkaw_ruleset/microsoft_non_ip.txt' },
      download_domainset: { type: 'http', behavior: 'domain', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/domainset/download.txt', path: './rule_set/sukkaw_ruleset/download_domainset.txt' },
      download_non_ip: { type: 'http', behavior: 'domain', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/download.txt', path: './rule_set/sukkaw_ruleset/download_non_ip.txt' },
      lan_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/lan.txt', path: './rule_set/sukkaw_ruleset/lan_non_ip.txt' },
      lan_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/ip/lan.txt', path: './rule_set/sukkaw_ruleset/lan_ip.txt' },
      domestic_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/domestic.txt', path: './rule_set/sukkaw_ruleset/domestic_non_ip.txt' },
      direct_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/direct.txt', path: './rule_set/sukkaw_ruleset/direct_non_ip.txt' },
      global_non_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/non_ip/global.txt', path: './rule_set/sukkaw_ruleset/global_non_ip.txt' },
      domestic_ip: { type: 'http', behavior: 'classical', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/ip/domestic.txt', path: './rule_set/sukkaw_ruleset/domestic_ip.txt' },
      china_ip: { type: 'http', behavior: 'ipcidr', interval: 43200, format: 'text', proxy: '节点选择', url: 'https://ruleset.skk.moe/Clash/ip/china_ip.txt', path: './rule_set/sukkaw_ruleset/china_ip.txt' }
    }
  };
  
  return `# Clash 配置文件 - Sub-Hub 自动生成
# 生成时间: ${new Date().toISOString()}

${convertToYaml(config)}`;
}

// 生成空的 Clash 配置
function generateEmptyClashConfig() {
  return generateClashConfig([]);
}

// 对象转 YAML 函数
function convertToYaml(obj, indent = 0) {
  const spaces = '  '.repeat(indent);
  let yaml = '';
  
  for (const [key, value] of Object.entries(obj)) {
    let yamlKey = key;
    if (key.includes(' ') || key.includes('@') || key.includes('&') || 
        key.includes('*') || key.includes('?') || key.includes('>') || 
        key.includes('<') || key.includes('!') || key.includes('%') || 
        key.includes('^') || key.includes('`') || /^\d/.test(key) || 
        key === '' || /^(true|false|null|yes|no|on|off)$/i.test(key)) {
      yamlKey = `"${key.replace(/"/g, '\\"')}"`;
    }
    
    if (value === null || value === undefined) {
      yaml += `${spaces}${yamlKey}: null\n`;
    } else if (typeof value === 'boolean') {
      yaml += `${spaces}${yamlKey}: ${value}\n`;
    } else if (typeof value === 'number') {
      yaml += `${spaces}${yamlKey}: ${value}\n`;
    } else if (typeof value === 'string') {
      const needsQuotes = value === '' ||
                         /^\s/.test(value) || /\s$/.test(value) ||
                         /^(true|false|null|yes|no|on|off)$/i.test(value) ||
                         /^[+-]?\d+$/.test(value) ||
                         /^[+-]?\d*\.\d+$/.test(value) ||
                         value.includes('\n') ||
                         value.includes('"');
      
      if (needsQuotes) {
        const escapedValue = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        yaml += `${spaces}${yamlKey}: "${escapedValue}"\n`;
      } else {
        yaml += `${spaces}${yamlKey}: ${value}\n`;
      }
    } else if (Array.isArray(value)) {
      if (value.length === 0) {
        yaml += `${spaces}${yamlKey}: []\n`;
      } else {
        yaml += `${spaces}${yamlKey}:\n`;
        for (const item of value) {
          if (typeof item === 'object' && item !== null) {
            yaml += `${spaces}  -\n`;
            const itemYaml = convertToYaml(item, 0);
            yaml += itemYaml.split('\n').map(line => 
              line.trim() ? `${spaces}    ${line}` : ''
            ).filter(line => line).join('\n') + '\n';
          } else if (typeof item === 'string') {
            const needsQuotes = item.includes(':') || item.includes('#') || 
                               item.includes('"') || item.includes('\n') ||
                               item.includes('&') || item.includes('*') ||
                               item.includes('[') || item.includes(']') ||
                               item.includes('{') || item.includes('}') ||
                               item.includes('@') || item.includes('`') ||
                               /^\s/.test(item) || /\s$/.test(item) || 
                               item === '' || /^(true|false|null|yes|no|on|off)$/i.test(item) ||
                               (/^\d+$/.test(item) && item.length > 1) || 
                               (/^\d+\.\d+$/.test(item) && item.length > 1);
            
            if (needsQuotes) {
              const escapedItem = item.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
              yaml += `${spaces}  - "${escapedItem}"\n`;
            } else {
              yaml += `${spaces}  - ${item}\n`;
            }
          } else {
            yaml += `${spaces}  - ${item}\n`;
          }
        }
      }
    } else if (typeof value === 'object' && value !== null) {
      yaml += `${spaces}${yamlKey}:\n`;
      yaml += convertToYaml(value, indent + 1);
    }
  }
  
  return yaml;
}

// 解析 Hysteria2 节点为 Clash 格式
function parseHysteria2ToClash(hysteria2Link) {
  if (!hysteria2Link.startsWith(NODE_TYPES.HYSTERIA2)) return null;
  
  try {
    const url = new URL(hysteria2Link);
    if (!url.hostname || !url.port) return null;
    
    const params = new URLSearchParams(url.search);
    const node = {
      name: url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点',
      type: 'hysteria2',
      server: url.hostname,
      port: parseInt(url.port),
      password: url.username || params.get('password') || '',
      'skip-cert-verify': true
    };
    
    const upMbps = params.get('upmbps') || params.get('up');
    const downMbps = params.get('downmbps') || params.get('down');
    if (upMbps) node.up = upMbps;
    if (downMbps) node.down = downMbps;
    
    const sni = params.get('sni');
    if (sni) node.sni = safeDecodeURIComponent(sni);
    
    const alpn = params.get('alpn');
    if (alpn) node.alpn = alpn.split(',').map(s => s.trim());
    
    const obfs = params.get('obfs');
    if (obfs) {
      node.obfs = safeDecodeURIComponent(obfs);
      const obfsPassword = params.get('obfs-password');
      if (obfsPassword) node['obfs-password'] = safeDecodeURIComponent(obfsPassword);
    }
    
    const cc = params.get('cc');
    if (cc) node.cc = cc;
    
    return node;
  } catch {
    return null;
  }
}

// 解析 TUIC 节点为 Clash 格式
function parseTuicToClash(tuicLink) {
  if (!tuicLink.startsWith(NODE_TYPES.TUIC)) return null;
  
  try {
    const url = new URL(tuicLink);
    if (!url.hostname || !url.port) return null;
    
    const params = new URLSearchParams(url.search);
    const node = {
      name: url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点',
      type: 'tuic',
      server: url.hostname,
      port: parseInt(url.port),
      uuid: url.username || params.get('uuid') || '',
      password: url.password || params.get('password') || '',
      'skip-cert-verify': true
    };
    
    const version = params.get('version') || params.get('v');
    if (version) node.version = parseInt(version);
    
    const sni = params.get('sni');
    if (sni) node.sni = safeDecodeURIComponent(sni);
    
    const alpn = params.get('alpn');
    if (alpn) node.alpn = alpn.split(',').map(s => s.trim());
    
    const udpRelayMode = params.get('udp_relay_mode') || params.get('udp-relay-mode');
    if (udpRelayMode) node['udp-relay-mode'] = udpRelayMode;
    
    const cc = params.get('congestion_control') || params.get('cc');
    if (cc) node['congestion-control'] = cc;
    
    const disableSni = params.get('disable_sni');
    if (disableSni === 'true' || disableSni === '1') node['disable-sni'] = true;
    
    const reduceRtt = params.get('reduce_rtt');
    if (reduceRtt === 'true' || reduceRtt === '1') node['reduce-rtt'] = true;
    
    return node;
  } catch {
    return null;
  }
}

// 解析 Hysteria2 链接为 Surge 格式
function parseHysteria2ToSurge(hysteria2Link) {
  if (!hysteria2Link.startsWith(NODE_TYPES.HYSTERIA2)) return null;
  
  try {
    const url = new URL(hysteria2Link);
    if (!url.hostname || !url.port) return null;
    
    const params = new URLSearchParams(url.search);
    const nodeName = url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点';
    const password = url.username || params.get('password') || '';
    
    const configParts = [
      `${nodeName} = hysteria2`,
      url.hostname,
      url.port,
      `password=${password}`
    ];
    
    const upMbps = params.get('upmbps') || params.get('up');
    const downMbps = params.get('downmbps') || params.get('down');
    if (upMbps) configParts.push(`up=${upMbps}`);
    if (downMbps) configParts.push(`down=${downMbps}`);
    
    const sni = params.get('sni');
    if (sni) configParts.push(`sni=${safeDecodeURIComponent(sni)}`);
    
    const alpn = params.get('alpn');
    if (alpn) configParts.push(`alpn=${alpn}`);
    
    const obfs = params.get('obfs');
    if (obfs) {
      configParts.push(`obfs=${safeDecodeURIComponent(obfs)}`);
      const obfsPassword = params.get('obfs-password');
      if (obfsPassword) configParts.push(`obfs-password=${safeDecodeURIComponent(obfsPassword)}`);
    }
    
    const cc = params.get('cc');
    if (cc) configParts.push(`cc=${cc}`);
    
    configParts.push('skip-cert-verify=true');
    
    return configParts.join(', ');
  } catch (error) {
    return null;
  }
}

// 解析 TUIC 链接为 Surge 格式
function parseTuicToSurge(tuicLink) {
  if (!tuicLink.startsWith(NODE_TYPES.TUIC)) return null;
  
  try {
    const url = new URL(tuicLink);
    if (!url.hostname || !url.port) return null;
    
    const params = new URLSearchParams(url.search);
    const nodeName = url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点';
    const uuid = url.username || params.get('uuid') || '';
    const password = url.password || params.get('password') || '';
    
    const configParts = [
      `${nodeName} = tuic`,
      url.hostname,
      url.port,
      `uuid=${uuid}`,
      `password=${password}`
    ];
    
    const version = params.get('version') || params.get('v') || '5';
    configParts.push(`version=${version}`);
    
    const sni = params.get('sni') || url.hostname;
    configParts.push(`sni=${safeDecodeURIComponent(sni)}`);
    
    const alpn = params.get('alpn');
    if (alpn) configParts.push(`alpn=${alpn}`);
    
    const allowInsecure = params.get('allow_insecure') || params.get('allowInsecure');
    if (allowInsecure === 'true' || allowInsecure === '1') {
      configParts.push('skip-cert-verify=true');
    } else {
      configParts.push('skip-cert-verify=false');
    }
    
    const udpRelayMode = params.get('udp_relay_mode') || params.get('udp-relay-mode');
    if (udpRelayMode) configParts.push(`udp-relay-mode=${udpRelayMode}`);
    
    const cc = params.get('congestion_control') || params.get('congestion-control') || params.get('cc');
    if (cc) configParts.push(`congestion-control=${cc}`);
    
    const disableSni = params.get('disable_sni');
    if (disableSni === 'true' || disableSni === '1') configParts.push('disable-sni=true');
    
    const reduceRtt = params.get('reduce_rtt');
    if (reduceRtt === 'true' || reduceRtt === '1') configParts.push('reduce-rtt=true');
    
    return configParts.join(', ');
  } catch (error) {
    return null;
  }
}
