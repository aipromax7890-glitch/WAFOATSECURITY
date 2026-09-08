import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import path from 'path';
import httpProxy from 'http-proxy';
import { Server as SocketIOServer } from 'socket.io';
import { createServer as createViteServer } from 'vite';
import { wafEngine, SecurityAlert } from './server/wafCore.ts';
import { tenantManager, Tenant, normalizeDomain, normalizeUpstream } from './server/tenantManager.ts';
import { analyzeSecurityIncident, chatWithCopilot } from './server/geminiCopilot.ts';

const app = express();
const server = http.createServer(app);
const PORT = 3000;

// Initialize Socket.io
const io = new SocketIOServer(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Initialize Reverse Proxy
const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  ws: true,
  timeout: 10000,
  proxyTimeout: 10000
});

// Handle proxy request body re-streaming & real headers
proxy.on('proxyReq', (proxyReq, req: any) => {
  if (req._clientIp) {
    proxyReq.setHeader('X-Forwarded-For', req._clientIp);
    proxyReq.setHeader('X-Real-IP', req._clientIp);
  }
  proxyReq.setHeader('X-WAF-Inspected', 'OAT-Security-Universal-WAF');

  // If express.json() or express.urlencoded() already consumed the stream, re-write body
  if (req.rawBody) {
    proxyReq.setHeader('Content-Length', Buffer.byteLength(req.rawBody));
    proxyReq.write(req.rawBody);
  } else if (req.body && Object.keys(req.body).length > 0) {
    const bodyData = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
    proxyReq.write(bodyData);
  }
});

// Robust error handler for upstream failures
proxy.on('error', (err: any, req: any, res: any) => {
  console.error('[Reverse Proxy Upstream Error]:', err.message);
  if (res.headersSent) return;

  const target = req._targetUpstream || 'upstream server';
  const isPrivateIp = /(^192\.168\.)|(^10\.)|(^172\.(1[6-9]|2[0-9]|3[0-1])\.)|(^127\.)/.test(target);

  res.writeHead(502, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      status: 502,
      error: 'Bad Gateway - Upstream Unreachable',
      wafInspection: 'PASSED',
      upstreamTarget: target,
      code: err.code || 'UPSTREAM_CONNECTION_FAILED',
      message: isPrivateIp
        ? `WAF inspection passed successfully, but the configured upstream target (${target}) is a private network address (LAN) that is unreachable from this cloud container. If you are testing locally, ensure network routing or expose your local server with a tunnel.`
        : `Failed to connect to upstream server (${target}): ${err.message}. Please verify the target domain/IP and port are active.`,
      timestamp: new Date().toISOString()
    })
  );
});

// In-memory access logs buffer
interface AccessLog {
  id: string;
  timestamp: string;
  clientIp: string;
  method: string;
  url: string;
  status: number;
  durationMs: number;
  bytes: number;
  tenantDomain: string;
  wafAction: 'PASSED' | 'BLOCKED' | 'MONITORED' | 'BANNED';
  userAgent: string;
}
const accessLogs: AccessLog[] = [];
function logAccess(item: AccessLog) {
  accessLogs.unshift(item);
  if (accessLogs.length > 500) accessLogs.pop();
  io.emit('access:log', item);
}

// Connect WAF Engine callbacks to Socket.io real-time push
wafEngine.setCallbacks(
  (alert: SecurityAlert) => {
    io.emit('attack:detected', alert);
    io.emit('stats:updated', getOverviewStats());
  },
  strikeData => {
    io.emit('strike:updated', strikeData);
    if (strikeData.isBanned) {
      io.emit('ip:banned', strikeData);
    }
  }
);

// Rolling attack rates & inspection performance metrics
const attackTimePoints: Array<{ time: string; count: number; blocked: number }> = [];
let totalInspectionMs = 0;
let totalInspectedCount = 0;

function recordInspectionMetrics(durationMs: number, isAttack: boolean) {
  totalInspectionMs += durationMs;
  totalInspectedCount += 1;

  const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const last = attackTimePoints[attackTimePoints.length - 1];
  if (last && last.time === nowStr) {
    last.count += 1;
    if (isAttack) last.blocked += 1;
  } else {
    attackTimePoints.push({ time: nowStr, count: 1, blocked: isAttack ? 1 : 0 });
    if (attackTimePoints.length > 15) attackTimePoints.shift();
  }
}

function getOverviewStats() {
  const allTenants = tenantManager.getAll();
  const alerts = wafEngine.getAlerts();
  const blacklist = wafEngine.getBlacklist();
  const strikes = wafEngine.getStrikes();

  const totalRequests = allTenants.reduce((acc, t) => acc + t.stats.totalRequests, 0);
  const totalBlocked = allTenants.reduce((acc, t) => acc + t.stats.blockedAttacks, 0);

  // Categorical threat distribution
  const categoryDistribution: Record<string, number> = {
    SQLi: 0,
    XSS: 0,
    LFI: 0,
    RCE: 0,
    CSRF: 0,
    Malware: 0,
    'DDoS/RateLimit': 0,
    Other: 0
  };

  alerts.forEach(a => {
    if (categoryDistribution[a.category] !== undefined) {
      categoryDistribution[a.category] += 1;
    } else {
      categoryDistribution.Other += 1;
    }
  });

  const avgLatency =
    totalInspectedCount > 0 ? (totalInspectionMs / totalInspectedCount).toFixed(2) : '0.00';

  return {
    totalRequests,
    totalBlocked,
    bannedIpCount: blacklist.length,
    activeStrikesCount: Object.values(strikes).filter(s => s.count > 0 && s.count < 3).length,
    tenantCount: allTenants.length,
    activeRulesCount: wafEngine.getRules().filter(r => r.enabled).length,
    categoryDistribution,
    recentRate: attackTimePoints,
    averageLatencyMs: `${avgLatency}ms`
  };
}

// Body parsing with raw buffer capture for accurate WAF inspection
app.use(
  express.json({
    limit: '10mb',
    verify: (req: any, _res, buf) => {
      req.rawBody = buf.toString();
    }
  })
);
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Helper to extract actual client IP
function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0];
    return ips.trim().replace(/^::ffff:/, '');
  }
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return Array.isArray(realIp) ? realIp[0].trim() : realIp.trim();
  }
  return (req.socket.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');
}

// -------------------------------------------------------------
// GATEWAY ROUTING & DYNAMIC REVERSE PROXY MIDDLEWARE
// -------------------------------------------------------------
app.use(async (req: Request, res: Response, next: NextFunction) => {
  // 1. Pass through internal API, Socket.io, and Vite static assets
  if (
    req.path.startsWith('/api/') ||
    req.path.startsWith('/socket.io/') ||
    req.path.startsWith('/@vite') ||
    req.path.startsWith('/@fs') ||
    req.path.startsWith('/src/') ||
    req.path.startsWith('/node_modules/') ||
    req.path.endsWith('.js') ||
    req.path.endsWith('.css') ||
    req.path.endsWith('.ts') ||
    req.path.endsWith('.tsx') ||
    req.path.endsWith('.svg') ||
    req.path.endsWith('.png') ||
    req.path.endsWith('.ico')
  ) {
    return next();
  }

  // 2. Resolve target tenant
  let targetTenant: Tenant | undefined;
  let targetPath = req.url;

  // Direct gateway path pattern: /gateway/:identifier/*
  // :identifier can be tenant ID, client domain, or IP:Port (e.g. 192.168.100.75:8081)
  const gatewayMatch = req.path.match(/^\/gateway\/([^/]+)(\/.*)?$/);
  if (gatewayMatch) {
    const identifier = decodeURIComponent(gatewayMatch[1]);
    targetTenant = tenantManager.getById(identifier) || tenantManager.getByDomain(identifier);

    if (targetTenant) {
      targetPath = gatewayMatch[2] || '/';
      if (req.url.includes('?')) {
        targetPath += req.url.substring(req.url.indexOf('?'));
      }
    } else {
      // If identifier was not found in tenants list
      return res.status(404).json({
        statusCode: 404,
        status: 'TENANT_NOT_FOUND',
        wafShield: 'OAT Security Universal WAF',
        message: `No active tenant registered for identifier "${identifier}". Please auto-provision this endpoint in the SOC Dashboard.`
      });
    }
  }

  // Header matching (X-Tenant-Domain or X-Tenant-ID)
  if (!targetTenant) {
    const headerDomain = req.headers['x-tenant-domain'] as string;
    const headerId = req.headers['x-tenant-id'] as string;
    if (headerDomain) targetTenant = tenantManager.getByDomain(headerDomain);
    if (!targetTenant && headerId) targetTenant = tenantManager.getById(headerId);
  }

  // Host header matching (supports domain or IP:port)
  if (!targetTenant && req.headers.host) {
    targetTenant = tenantManager.getByDomain(req.headers.host);
  }

  // If no tenant matched:
  if (!targetTenant) {
    // Check if it is a clean navigation request to the SOC Dashboard SPA
    const isCleanSpaRoute =
      (req.path === '/' ||
        req.path === '/alerts' ||
        req.path === '/threats' ||
        req.path === '/tenants' ||
        req.path === '/logs' ||
        req.path === '/control' ||
        req.path === '/copilot') &&
      req.method === 'GET' &&
      Object.keys(req.query || {}).length === 0;

    if (isCleanSpaRoute) {
      return next();
    }

    // Direct probe/attack against the gateway
    const all = tenantManager.getAll();
    if (all.length > 0) {
      targetTenant = all[0];
      targetPath = req.url;
    } else {
      // Default perimeter context when 0 tenants are configured
      targetTenant = {
        id: 'system-perimeter',
        name: 'Perimeter Gateway Shield',
        domain: req.headers.host || 'gateway.oatsec.io',
        upstream: 'http://127.0.0.1:3000',
        mode: 'BLOCKING',
        createdAt: new Date().toISOString(),
        status: 'active',
        rateLimitPerMin: 300,
        stats: { totalRequests: 0, blockedAttacks: 0, bandwidthBytes: 0 }
      };
      targetPath = req.url;
    }
  }

  const clientIp = getClientIp(req);

  // 3. Enforce Rate Limiting & DDoS Shield
  const rateCheck = wafEngine.checkRateLimit(
    clientIp,
    targetTenant.id,
    targetTenant.rateLimitPerMin,
    targetTenant.domain
  );

  if (!rateCheck.allowed) {
    recordInspectionMetrics(1, true);
    logAccess({
      id: 'ACC-' + Date.now().toString(36),
      timestamp: new Date().toISOString(),
      clientIp,
      method: req.method,
      url: targetPath,
      status: 429,
      durationMs: 1,
      bytes: 380,
      tenantDomain: targetTenant.domain,
      wafAction: 'BLOCKED',
      userAgent: String(req.headers['user-agent'] || 'Unknown')
    });

    res.setHeader('Retry-After', String(rateCheck.resetInSeconds));
    res.setHeader('X-RateLimit-Limit', String(rateCheck.limit));
    res.setHeader('X-RateLimit-Remaining', '0');
    res.setHeader('X-RateLimit-Reset', String(rateCheck.resetInSeconds));

    const wantsJson =
      (req.headers.accept || '').includes('application/json') ||
      req.headers['content-type'] === 'application/json';

    if (wantsJson) {
      return res.status(429).json({
        statusCode: 429,
        status: 'TOO_MANY_REQUESTS',
        wafShield: 'OAT Security L7 DDoS Protection',
        message: `Rate limit exceeded (${rateCheck.current}/${rateCheck.limit} req/min). Cloudflare-grade L7 DDoS rate limiting engaged.`,
        retryAfterSeconds: rateCheck.resetInSeconds,
        tenantDomain: targetTenant.domain
      });
    }

    res.status(429);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(rateCheck.blockPageHtml);
  }

  // 4. Execute Real-Time WAF Inspection
  const startTime = Date.now();
  const inspection = wafEngine.inspectRequest({
    clientIp,
    method: req.method,
    path: targetPath,
    rawUrl: targetPath,
    headers: req.headers,
    query: req.query,
    body: req.body || (req as any).rawBody,
    tenantId: targetTenant.id,
    tenantDomain: targetTenant.domain,
    wafMode: targetTenant.mode
  });

  const durationMs = Math.max(1, Date.now() - startTime);
  recordInspectionMetrics(durationMs, !inspection.passed || !!inspection.alert);

  if (targetTenant.id !== 'system-perimeter') {
    tenantManager.recordRequest(targetTenant.id, !inspection.passed, 500);
  }

  // 5. If WAF blocked the request (HTTP 403)
  if (!inspection.passed) {
    const action = inspection.isBanned ? 'BANNED' : 'BLOCKED';
    logAccess({
      id: 'ACC-' + Date.now().toString(36),
      timestamp: new Date().toISOString(),
      clientIp,
      method: req.method,
      url: targetPath,
      status: 403,
      durationMs,
      bytes: inspection.blockPageHtml?.length || 512,
      tenantDomain: targetTenant.domain,
      wafAction: action,
      userAgent: String(req.headers['user-agent'] || 'Unknown')
    });

    const wantsJson =
      (req.headers.accept || '').includes('application/json') ||
      req.headers['content-type'] === 'application/json';

    if (wantsJson) {
      return res.status(403).json({
        statusCode: 403,
        status: 'FORBIDDEN',
        wafShield: 'OAT Security Universal WAF',
        action,
        clientIp,
        tenantDomain: targetTenant.domain,
        alert: inspection.alert
          ? {
              id: inspection.alert.id,
              category: inspection.alert.category,
              rule: inspection.alert.ruleName,
              severity: inspection.alert.severity,
              strikes: inspection.alert.strikes
            }
          : undefined,
        message: 'Request was blocked by OAT Security real-time inspection engine.'
      });
    }

    res.status(403);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(inspection.blockPageHtml);
  }

  // 6. Request passed inspection or is in DETECTION_ONLY mode
  logAccess({
    id: 'ACC-' + Date.now().toString(36),
    timestamp: new Date().toISOString(),
    clientIp,
    method: req.method,
    url: targetPath,
    status: 200,
    durationMs,
    bytes: 1240,
    tenantDomain: targetTenant.domain,
    wafAction: inspection.alert ? 'MONITORED' : 'PASSED',
    userAgent: String(req.headers['user-agent'] || 'Unknown')
  });

  // If system perimeter fallback without actual upstream, respond with clean gateway status
  if (targetTenant.id === 'system-perimeter') {
    return res.json({
      status: 200,
      wafStatus: 'PASSED',
      message: 'OAT Security WAF Gateway active. Request passed perimeter inspection.',
      clientIp,
      timestamp: new Date().toISOString()
    });
  }

  // 7. Proxy directly and dynamically to upstream target
  (req as any)._clientIp = clientIp;
  (req as any)._targetUpstream = targetTenant.upstream;

  // Resolve base path from upstream target URI if configured
  let upstreamBase = '';
  try {
    const parsedUpstream = new URL(targetTenant.upstream);
    upstreamBase = parsedUpstream.pathname.replace(/\/+$/, '');
  } catch {}

  const finalPath = upstreamBase
    ? upstreamBase + (targetPath.startsWith('/') ? targetPath : '/' + targetPath)
    : targetPath;

  req.url = finalPath;
  proxy.web(req, res, { target: targetTenant.upstream, changeOrigin: true });
});

// -------------------------------------------------------------
// REST API FOR SOC DASHBOARD & CONTROL PANEL
// -------------------------------------------------------------

// Health Check
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    gateway: 'OAT Security Universal WAF',
    port: PORT,
    timestamp: new Date().toISOString()
  });
});

// 1. Overview Metrics
app.get('/api/overview', (_req: Request, res: Response) => {
  res.json(getOverviewStats());
});

app.get('/api/stats', (_req: Request, res: Response) => {
  res.json({ success: true, stats: getOverviewStats() });
});

// 2. Security Alerts
app.get('/api/alerts', (req: Request, res: Response) => {
  let list = wafEngine.getAlerts();
  const category = req.query.category as string;
  const severity = req.query.severity as string;
  const tenantId = req.query.tenantId as string;
  const search = ((req.query.search as string) || '').toLowerCase();

  if (category && category !== 'ALL') {
    list = list.filter(a => a.category.toLowerCase() === category.toLowerCase());
  }
  if (severity && severity !== 'ALL') {
    list = list.filter(a => a.severity === severity);
  }
  if (tenantId && tenantId !== 'ALL') {
    list = list.filter(a => a.tenantId === tenantId);
  }
  if (search) {
    list = list.filter(
      a =>
        a.clientIp.includes(search) ||
        a.ruleName.toLowerCase().includes(search) ||
        a.url.toLowerCase().includes(search) ||
        a.matchedSnippet.toLowerCase().includes(search)
    );
  }

  res.json({ alerts: list });
});

// 3. Threat Actors (Blacklist, Strikes, Whitelist)
app.get('/api/threat-actors', (_req: Request, res: Response) => {
  res.json({
    blacklist: wafEngine.getBlacklist(),
    whitelist: wafEngine.getWhitelist(),
    strikes: wafEngine.getStrikes(),
    settings: wafEngine.getSettings()
  });
});

app.post('/api/threat-actors/ban', (req: Request, res: Response) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP is required' });
  const entry = wafEngine.manualBanIp(ip, reason);
  res.json({ success: true, entry });
});

app.post('/api/threat-actors/unban', (req: Request, res: Response) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP is required' });
  const success = wafEngine.unbanIp(ip);
  res.json({ success });
});

app.post('/api/threat-actors/whitelist', (req: Request, res: Response) => {
  const { ip, description } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP is required' });
  const entry = wafEngine.addToWhitelist(ip, description);
  res.json({ success: true, entry });
});

app.delete('/api/threat-actors/whitelist/:ip', (req: Request, res: Response) => {
  const ip = req.params.ip;
  const success = wafEngine.removeFromWhitelist(ip);
  res.json({ success });
});

app.put('/api/threat-actors/settings', (req: Request, res: Response) => {
  const updated = wafEngine.updateSettings(req.body);
  res.json({ success: true, settings: updated });
});

// 4. Tenant Auto-Provisioning & Management
app.get('/api/tenants', (_req: Request, res: Response) => {
  res.json({ tenants: tenantManager.getAll() });
});

app.post('/api/tenants', (req: Request, res: Response) => {
  const { name, domain, upstream, mode, rateLimitPerMin } = req.body;
  if (!domain || !upstream) {
    return res.status(400).json({ error: 'Domain/IP and upstream target are required' });
  }
  const created = tenantManager.autoProvision({ name, domain, upstream, mode, rateLimitPerMin });
  io.emit('tenant:provisioned', created);
  res.status(201).json({ success: true, tenant: created });
});

app.put('/api/tenants/:id', (req: Request, res: Response) => {
  const id = req.params.id;
  const updated = tenantManager.updateTenant(id, req.body);
  if (!updated) return res.status(404).json({ error: 'Tenant not found' });
  io.emit('tenant:updated', updated);
  res.json({ success: true, tenant: updated });
});

app.delete('/api/tenants/:id', (req: Request, res: Response) => {
  const id = req.params.id;
  const deleted = tenantManager.deleteTenant(id);
  if (!deleted) return res.status(404).json({ error: 'Tenant not found' });
  io.emit('tenant:deleted', { id });
  res.json({ success: true });
});

// 5. WAF Rules Engine
app.get('/api/rules', (_req: Request, res: Response) => {
  res.json({ rules: wafEngine.getRules() });
});

app.post('/api/rules', (req: Request, res: Response) => {
  const { name, category, severity, pattern, target, description } = req.body;
  if (!name || !pattern || !category) {
    return res.status(400).json({ error: 'Rule name, pattern, and category are required' });
  }
  const newRule = wafEngine.addCustomRule({
    name,
    category,
    severity: severity || 'HIGH',
    pattern,
    target: target || 'all',
    description: description || 'Custom User Rule',
    enabled: true
  });
  res.status(201).json({ success: true, rule: newRule });
});

app.put('/api/rules/:id/toggle', (req: Request, res: Response) => {
  const { enabled } = req.body;
  const updated = wafEngine.toggleRule(req.params.id, Boolean(enabled));
  if (!updated) return res.status(404).json({ error: 'Rule not found' });
  res.json({ success: true, rule: updated });
});

app.delete('/api/rules/:id', (req: Request, res: Response) => {
  const success = wafEngine.deleteRule(req.params.id);
  res.json({ success });
});

// 6. Access Logs
app.get('/api/access-logs', (req: Request, res: Response) => {
  const filter = (req.query.action as string) || 'ALL';
  let logs = accessLogs;
  if (filter !== 'ALL') {
    logs = logs.filter(l => l.wafAction === filter);
  }
  res.json({ logs });
});

app.get('/api/logs', (req: Request, res: Response) => {
  const filter = (req.query.action as string) || 'ALL';
  let logs = accessLogs;
  if (filter !== 'ALL') {
    logs = logs.filter(l => l.wafAction === filter);
  }
  res.json({ success: true, logs });
});

// 7. Gemini AI SOC Copilot Incident Analysis & Chat
app.post('/api/ai/analyze', async (req: Request, res: Response) => {
  try {
    const result = await analyzeSecurityIncident(req.body);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: 'AI Analysis failed', details: err.message });
  }
});

app.post('/api/copilot/analyze', async (req: Request, res: Response) => {
  try {
    const alert = req.body && req.body.alert ? req.body.alert : req.body || {};
    console.log('[Copilot] Analyze request received for incident:', alert.id);
    const result = await analyzeSecurityIncident({
      incidentId: alert.id || 'INC-TEST',
      category: alert.category || 'SQLi',
      ruleName: alert.ruleName || 'SQL Injection',
      severity: alert.severity || 'HIGH',
      payload: alert.matchedSnippet || '',
      url: alert.url || '/',
      method: alert.method || 'GET',
      clientIp: alert.clientIp || '127.0.0.1',
      targetDomain: alert.tenantDomain || 'localhost'
    });
    console.log('[Copilot] Analyze completed successfully');
    res.json(result);
  } catch (err: any) {
    console.error('[Copilot] Analyze error:', err);
    res.status(500).json({ error: 'Copilot analysis failed', details: err.message });
  }
});

app.post('/api/copilot/chat', async (req: Request, res: Response) => {
  try {
    const body = req.body || {};
    const query = body.query || '';
    const history = body.history || [];
    console.log('[Copilot] Chat query received:', query);
    const response = await chatWithCopilot(query, history);
    console.log('[Copilot] Chat response generated');
    res.json({ response });
  } catch (err: any) {
    console.error('[Copilot] Chat error:', err);
    res.status(500).json({ error: 'Copilot chat failed', details: err.message });
  }
});

// ACL Blacklist & Whitelist Aliases
app.get('/api/acl/blacklist', (_req: Request, res: Response) => {
  res.json({ success: true, blacklist: wafEngine.getBlacklist() });
});

app.post('/api/acl/blacklist', (req: Request, res: Response) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP is required' });
  wafEngine.manualBanIp(ip, reason);
  res.json({ success: true, blacklist: wafEngine.getBlacklist() });
});

app.delete('/api/acl/blacklist/:ip', (req: Request, res: Response) => {
  wafEngine.unbanIp(req.params.ip);
  res.json({ success: true, blacklist: wafEngine.getBlacklist() });
});

app.get('/api/acl/whitelist', (_req: Request, res: Response) => {
  res.json({ success: true, whitelist: wafEngine.getWhitelist() });
});

app.post('/api/acl/whitelist', (req: Request, res: Response) => {
  const { ip, description } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP is required' });
  wafEngine.addToWhitelist(ip, description);
  res.json({ success: true, whitelist: wafEngine.getWhitelist() });
});

app.delete('/api/acl/whitelist/:ip', (req: Request, res: Response) => {
  wafEngine.removeFromWhitelist(req.params.ip);
  res.json({ success: true, whitelist: wafEngine.getWhitelist() });
});

app.get('/api/acl/strikes', (_req: Request, res: Response) => {
  res.json({ success: true, strikes: wafEngine.getStrikes() });
});

// -------------------------------------------------------------
// VITE SPA INTEGRATION
// -------------------------------------------------------------
async function start() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[OAT Security WAF Gateway] Server running at http://0.0.0.0:${PORT}`);
  });
}

start();
