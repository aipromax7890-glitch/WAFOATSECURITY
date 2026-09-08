import fs from 'fs';
import path from 'path';

export interface WafRule {
  id: string;
  name: string;
  category: 'SQLi' | 'XSS' | 'LFI' | 'RCE' | 'CSRF' | 'Malware' | 'Custom';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  enabled: boolean;
  pattern: string;
  target?: 'all' | 'url' | 'query' | 'headers' | 'body';
  description: string;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  clientIp: string;
  method: string;
  url: string;
  tenantId: string;
  tenantDomain: string;
  ruleId: string;
  ruleName: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  matchedTarget: 'URL' | 'QUERY' | 'HEADER' | 'BODY';
  matchedSnippet: string;
  action: 'BLOCKED' | 'MONITORED';
  userAgent: string;
  country: string;
  strikes: number;
  isBanned: boolean;
}

export interface BlacklistedIp {
  ip: string;
  reason: string;
  bannedAt: string;
  strikes: number;
  country: string;
  lastUserAgent: string;
}

export interface WhitelistedIp {
  ip: string;
  description: string;
  addedAt: string;
}

export interface StrikeRecord {
  ip: string;
  count: number;
  lastStrike: string;
  country: string;
  incidents: string[];
}

const DATA_DIR = path.join(process.cwd(), 'data');
const RULES_FILE = path.join(DATA_DIR, 'rules.json');
const ACL_FILE = path.join(DATA_DIR, 'acl.json');

class WafEngine {
  private rules: WafRule[] = [];
  private blacklist: BlacklistedIp[] = [];
  private whitelist: WhitelistedIp[] = [];
  private strikes: Record<string, StrikeRecord> = {};
  private settings = {
    strikeThreshold: 3,
    strikeWindowMinutes: 60,
    defaultWafMode: 'BLOCKING' as 'BLOCKING' | 'DETECTION_ONLY'
  };

  private recentAlerts: SecurityAlert[] = [];
  private maxAlertHistory = 500;
  private onAlertCallback?: (alert: SecurityAlert) => void;
  private onStrikeCallback?: (data: { ip: string; strikes: number; isBanned: boolean; reason?: string }) => void;
  private rateLimitStore: Map<string, { count: number; resetAt: number }> = new Map();

  constructor() {
    this.loadRules();
    this.loadAcl();
    // Cleanup rate limit store every 2 minutes
    setInterval(() => {
      const now = Date.now();
      for (const [k, v] of this.rateLimitStore.entries()) {
        if (now > v.resetAt) this.rateLimitStore.delete(k);
      }
    }, 120000);
  }

  public setCallbacks(
    onAlert: (alert: SecurityAlert) => void,
    onStrike: (data: { ip: string; strikes: number; isBanned: boolean; reason?: string }) => void
  ) {
    this.onAlertCallback = onAlert;
    this.onStrikeCallback = onStrike;
  }

  private loadRules() {
    try {
      if (fs.existsSync(RULES_FILE)) {
        const raw = fs.readFileSync(RULES_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        this.rules = parsed.rules || [];
      }
    } catch (err) {
      console.error('Error loading WAF rules:', err);
    }
  }

  private loadAcl() {
    try {
      if (fs.existsSync(ACL_FILE)) {
        const raw = fs.readFileSync(ACL_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        this.blacklist = parsed.blacklist || [];
        this.whitelist = parsed.whitelist || [];
        this.strikes = parsed.strikes || {};
        if (parsed.settings) {
          this.settings = { ...this.settings, ...parsed.settings };
        }
      }
    } catch (err) {
      console.error('Error loading ACL file:', err);
    }
  }

  public saveAcl() {
    try {
      fs.writeFileSync(
        ACL_FILE,
        JSON.stringify(
          {
            blacklist: this.blacklist,
            whitelist: this.whitelist,
            strikes: this.strikes,
            settings: this.settings
          },
          null,
          2
        ),
        'utf-8'
      );
    } catch (err) {
      console.error('Error saving ACL file:', err);
    }
  }

  public saveRules() {
    try {
      fs.writeFileSync(RULES_FILE, JSON.stringify({ rules: this.rules }, null, 2), 'utf-8');
    } catch (err) {
      console.error('Error saving rules file:', err);
    }
  }

  // --- Normalizer & Decoder ---
  public normalizePayload(str: string): string {
    if (!str || typeof str !== 'string') return '';
    let decoded = str;

    // Multi-pass URL decoding (to combat double url encoding %252e%252e)
    for (let i = 0; i < 3; i++) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch {
        break;
      }
    }

    // Replace unicode/hex encodings (\u003c -> <, %3c -> <)
    decoded = decoded.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    decoded = decoded.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));

    // HTML entities
    decoded = decoded
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"')
      .replace(/&#39;/gi, "'")
      .replace(/&amp;/gi, '&');

    // Remove null bytes
    decoded = decoded.replace(/\0/g, '');

    return decoded;
  }

  // Helper to extract country by IP simulation/heuristic
  public guessCountry(ip: string): string {
    if (ip.startsWith('194.') || ip.startsWith('195.')) return 'RU';
    if (ip.startsWith('45.') || ip.startsWith('185.220')) return 'DE';
    if (ip.startsWith('103.') || ip.startsWith('114.')) return 'ID';
    if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.')) return 'LAN';
    if (ip.startsWith('8.8.') || ip.startsWith('34.') || ip.startsWith('35.')) return 'US';
    return 'SG';
  }

  // Check if IP is in Whitelist
  public isWhitelisted(ip: string): boolean {
    const cleanIp = (ip || '').trim().replace(/^::ffff:/, '');
    return this.whitelist.some(w => w.ip === cleanIp || cleanIp.startsWith(w.ip));
  }

  // Check if IP is in Blacklist
  public isBlacklisted(ip: string): BlacklistedIp | undefined {
    const cleanIp = (ip || '').trim().replace(/^::ffff:/, '');
    return this.blacklist.find(b => b.ip === cleanIp);
  }

  // Strike handler: 3x Strike Shield
  public recordStrike(ip: string, incidentDesc: string, userAgent: string): { strikes: number; isBanned: boolean } {
    const cleanIp = (ip || '').trim().replace(/^::ffff:/, '');
    if (this.isWhitelisted(cleanIp)) {
      return { strikes: 0, isBanned: false };
    }

    const existingBlacklist = this.isBlacklisted(cleanIp);
    if (existingBlacklist) {
      return { strikes: existingBlacklist.strikes, isBanned: true };
    }

    if (!this.strikes[cleanIp]) {
      this.strikes[cleanIp] = {
        ip: cleanIp,
        count: 0,
        lastStrike: new Date().toISOString(),
        country: this.guessCountry(cleanIp),
        incidents: []
      };
    }

    const record = this.strikes[cleanIp];
    record.count += 1;
    record.lastStrike = new Date().toISOString();
    record.incidents.push(incidentDesc);
    if (record.incidents.length > 20) record.incidents.shift();

    let isBanned = false;
    if (record.count >= this.settings.strikeThreshold) {
      isBanned = true;
      const bannedEntry: BlacklistedIp = {
        ip: cleanIp,
        reason: `Automated 3x Strike Shield: Exceeded threshold (${record.count} critical attacks)`,
        bannedAt: new Date().toISOString(),
        strikes: record.count,
        country: record.country,
        lastUserAgent: userAgent || 'Unknown'
      };
      this.blacklist.push(bannedEntry);
      this.saveAcl();

      if (this.onStrikeCallback) {
        this.onStrikeCallback({
          ip: cleanIp,
          strikes: record.count,
          isBanned: true,
          reason: bannedEntry.reason
        });
      }
    } else {
      this.saveAcl();
      if (this.onStrikeCallback) {
        this.onStrikeCallback({
          ip: cleanIp,
          strikes: record.count,
          isBanned: false
        });
      }
    }

    return { strikes: record.count, isBanned };
  }

  // Rate Limiting & DDoS Shield (Sliding Window per IP + Tenant)
  public checkRateLimit(
    clientIp: string,
    tenantId: string,
    limitPerMin: number,
    tenantDomain: string = 'Protected Host'
  ): {
    allowed: boolean;
    current: number;
    limit: number;
    remaining: number;
    resetInSeconds: number;
    blockPageHtml?: string;
    alert?: SecurityAlert;
  } {
    const cleanIp = (clientIp || '').trim().replace(/^::ffff:/, '');
    if (this.isWhitelisted(cleanIp)) {
      return { allowed: true, current: 1, limit: limitPerMin, remaining: limitPerMin, resetInSeconds: 60 };
    }

    const now = Date.now();
    const key = `${cleanIp}:${tenantId}`;
    let record = this.rateLimitStore.get(key);

    if (!record || now > record.resetAt) {
      record = { count: 1, resetAt: now + 60000 };
      this.rateLimitStore.set(key, record);
      return {
        allowed: true,
        current: 1,
        limit: limitPerMin,
        remaining: Math.max(0, limitPerMin - 1),
        resetInSeconds: 60
      };
    }

    record.count += 1;
    const remaining = Math.max(0, limitPerMin - record.count);
    const resetInSeconds = Math.max(1, Math.ceil((record.resetAt - now) / 1000));

    if (record.count > limitPerMin) {
      // If severe flood (> 1.5x limit), register auto-mitigation strike
      let strikeCount = 0;
      let nowBanned = false;
      if (record.count >= limitPerMin * 1.5) {
        const strikeRes = this.recordStrike(
          cleanIp,
          `HTTP Flood / L7 DDoS (${record.count} req/min exceeding limit ${limitPerMin})`,
          'High Frequency Flood'
        );
        strikeCount = strikeRes.strikes;
        nowBanned = strikeRes.isBanned;
      } else {
        const cur = this.strikes[cleanIp];
        strikeCount = cur ? cur.count : 0;
      }

      const incidentId = 'OAT-DDOS-' + Math.random().toString(36).substring(2, 8).toUpperCase();
      const alert: SecurityAlert = {
        id: incidentId,
        timestamp: new Date().toISOString(),
        clientIp: cleanIp,
        method: 'RATE_LIMIT',
        url: 'L7 DDoS Shield',
        tenantId,
        tenantDomain,
        ruleId: 'RULE-DDOS-001',
        ruleName: `Rate Limit Exceeded (${record.count}/${limitPerMin} req/min)`,
        category: 'DDoS/RateLimit',
        severity: 'HIGH',
        matchedTarget: 'HEADER',
        matchedSnippet: `Request volume: ${record.count} req/min (Tenant limit: ${limitPerMin})`,
        action: 'BLOCKED',
        userAgent: 'High Frequency Traffic',
        country: this.guessCountry(cleanIp),
        strikes: strikeCount,
        isBanned: nowBanned
      };

      this.recentAlerts.unshift(alert);
      if (this.recentAlerts.length > this.maxAlertHistory) this.recentAlerts.pop();
      if (this.onAlertCallback) this.onAlertCallback(alert);

      const blockPageHtml = this.generateBlockPageHtml({
        incidentId,
        clientIp: cleanIp,
        reason: `HTTP Request Flood: Exceeded tenant rate limit of ${limitPerMin} req/min. Anti-DDoS rate limiting engaged.`,
        strikes: strikeCount,
        ruleName: 'L7 DDoS / Rate Limiting Shield',
        category: 'RATE_LIMIT'
      });

      return {
        allowed: false,
        current: record.count,
        limit: limitPerMin,
        remaining: 0,
        resetInSeconds,
        blockPageHtml,
        alert
      };
    }

    return {
      allowed: true,
      current: record.count,
      limit: limitPerMin,
      remaining,
      resetInSeconds
    };
  }

  // Inspect Request
  public inspectRequest(params: {
    clientIp: string;
    method: string;
    path: string;
    rawUrl: string;
    headers: Record<string, any>;
    query: Record<string, any>;
    body: any;
    tenantId: string;
    tenantDomain: string;
    wafMode: 'BLOCKING' | 'DETECTION_ONLY';
  }): { passed: boolean; alert?: SecurityAlert; isBanned?: boolean; blockPageHtml?: string } {
    const cleanIp = (params.clientIp || '').trim().replace(/^::ffff:/, '');

    // 1. Check Whitelist
    if (this.isWhitelisted(cleanIp)) {
      return { passed: true };
    }

    // 2. Check Blacklist
    const blacklisted = this.isBlacklisted(cleanIp);
    if (blacklisted) {
      const blockPageHtml = this.generateBlockPageHtml({
        incidentId: 'OAT-BAN-' + Date.now().toString(36).toUpperCase(),
        clientIp: cleanIp,
        reason: blacklisted.reason,
        strikes: blacklisted.strikes,
        ruleName: 'IP Blacklist Enforced (ACL)',
        category: 'ACCESS_CONTROL'
      });
      return { passed: false, isBanned: true, blockPageHtml };
    }

    // 3. Prepare inspection items
    const userAgent = String(params.headers['user-agent'] || '');
    const referer = String(params.headers['referer'] || '');
    const cookie = String(params.headers['cookie'] || '');

    const candidates: Array<{ target: 'URL' | 'QUERY' | 'HEADER' | 'BODY'; raw: string }> = [];

    // URL & Path
    candidates.push({ target: 'URL', raw: params.path });
    candidates.push({ target: 'URL', raw: params.rawUrl });

    // Query parameters
    for (const [key, val] of Object.entries(params.query || {})) {
      candidates.push({ target: 'QUERY', raw: `${key}=${typeof val === 'object' ? JSON.stringify(val) : val}` });
    }

    // Headers
    candidates.push({ target: 'HEADER', raw: `user-agent: ${userAgent}` });
    if (referer) candidates.push({ target: 'HEADER', raw: `referer: ${referer}` });
    if (cookie) candidates.push({ target: 'HEADER', raw: `cookie: ${cookie}` });

    // Body
    if (params.body) {
      if (typeof params.body === 'string') {
        candidates.push({ target: 'BODY', raw: params.body });
      } else {
        candidates.push({ target: 'BODY', raw: JSON.stringify(params.body) });
      }
    }

    // 4. Test each enabled rule
    for (const rule of this.rules) {
      if (!rule.enabled) continue;

      let regex: RegExp;
      try {
        // Support (?i) flag if present in pattern string
        let pat = rule.pattern;
        let flags = 'i';
        if (pat.startsWith('(?i)')) {
          pat = pat.substring(4);
        }
        regex = new RegExp(pat, flags);
      } catch (err) {
        console.error(`Invalid regex in rule ${rule.id}:`, err);
        continue;
      }

      for (const cand of candidates) {
        if (rule.target && rule.target !== 'all') {
          if (rule.target === 'headers' && cand.target !== 'HEADER') continue;
          if (rule.target === 'url' && cand.target !== 'URL') continue;
          if (rule.target === 'query' && cand.target !== 'QUERY') continue;
          if (rule.target === 'body' && cand.target !== 'BODY') continue;
        }

        const normalized = this.normalizePayload(cand.raw);
        const match = regex.exec(normalized) || regex.exec(cand.raw);

        if (match) {
          // Attack Detected!
          const matchedSnippet = match[0].length > 120 ? match[0].substring(0, 120) + '...' : match[0];
          const incidentId = 'OAT-SEC-' + Math.random().toString(36).substring(2, 8).toUpperCase() + '-' + Date.now().toString(36).toUpperCase();

          // Evaluate Strikes
          let strikeCount = 0;
          let nowBanned = false;
          if (rule.severity === 'CRITICAL' || rule.severity === 'HIGH') {
            const strikeResult = this.recordStrike(cleanIp, `${rule.category}: ${rule.name}`, userAgent);
            strikeCount = strikeResult.strikes;
            nowBanned = strikeResult.isBanned;
          } else {
            const currentRec = this.strikes[cleanIp];
            strikeCount = currentRec ? currentRec.count : 0;
          }

          const action = params.wafMode === 'BLOCKING' ? 'BLOCKED' : 'MONITORED';

          const alert: SecurityAlert = {
            id: incidentId,
            timestamp: new Date().toISOString(),
            clientIp: cleanIp,
            method: params.method,
            url: params.rawUrl,
            tenantId: params.tenantId,
            tenantDomain: params.tenantDomain,
            ruleId: rule.id,
            ruleName: rule.name,
            category: rule.category,
            severity: rule.severity,
            matchedTarget: cand.target,
            matchedSnippet,
            action,
            userAgent,
            country: this.guessCountry(cleanIp),
            strikes: strikeCount,
            isBanned: nowBanned
          };

          this.recentAlerts.unshift(alert);
          if (this.recentAlerts.length > this.maxAlertHistory) {
            this.recentAlerts.pop();
          }

          if (this.onAlertCallback) {
            this.onAlertCallback(alert);
          }

          if (params.wafMode === 'BLOCKING') {
            const blockPageHtml = this.generateBlockPageHtml({
              incidentId,
              clientIp: cleanIp,
              reason: `Threat Signature Detected: [${rule.category}] ${rule.name}`,
              strikes: strikeCount,
              ruleName: rule.name,
              category: rule.category
            });
            return { passed: false, alert, isBanned: nowBanned, blockPageHtml };
          } else {
            // Detection only mode - alert logged, pass request
            return { passed: true, alert };
          }
        }
      }
    }

    return { passed: true };
  }

  // Custom OAT Security WAF Block Page generator
  public generateBlockPageHtml(params: {
    incidentId: string;
    clientIp: string;
    reason: string;
    strikes: number;
    ruleName: string;
    category: string;
  }): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>403 Forbidden - OAT Security WAF Shield</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --accent: #ef4444;
      --cyan: #06b6d4;
      --text: #f3f4f6;
      --muted: #9ca3af;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif; }
    body {
      background: radial-gradient(circle at 50% 20%, #172033 0%, #0b0f19 70%);
      color: var(--text);
      display: flex;
      min-height: 100vh;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .container {
      background: var(--card-bg);
      border: 1px solid rgba(239, 68, 68, 0.3);
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 30px rgba(239, 68, 68, 0.15);
      border-radius: 1rem;
      max-width: 600px;
      width: 100%;
      padding: 2.5rem;
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    .container::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 4px;
      background: linear-gradient(90deg, #ef4444, #f97316, #ef4444);
    }
    .badge-icon {
      width: 64px;
      height: 64px;
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 1.5rem;
      color: #ef4444;
      font-size: 28px;
    }
    h1 { font-size: 1.75rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem; }
    .subtitle { color: var(--muted); font-size: 0.95rem; margin-bottom: 2rem; line-height: 1.5; }
    .details-box {
      background: #0b0f19;
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1.25rem;
      text-align: left;
      font-size: 0.875rem;
      margin-bottom: 1.75rem;
    }
    .row { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
    .row:last-child { border-bottom: none; }
    .label { color: var(--muted); font-weight: 500; }
    .value { color: #fff; font-family: monospace; font-weight: 600; }
    .strike-pill {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 9999px;
      background: rgba(239, 68, 68, 0.2);
      color: #f87171;
      font-size: 0.75rem;
      font-weight: 700;
    }
    .footer { font-size: 0.8rem; color: #6b7280; display: flex; align-items: center; justify-content: center; gap: 0.5rem; }
    .brand { color: var(--cyan); font-weight: 600; }
  </style>
</head>
<body>
  <div class="container">
    <div class="badge-icon">🛡️</div>
    <h1>Access Denied (403 Forbidden)</h1>
    <p class="subtitle">Your request has been blocked by the <strong>OAT Security Cloud WAF</strong> due to anomalous or malicious signature patterns violating security policies.</p>
    
    <div class="details-box">
      <div class="row">
        <span class="label">Incident Reference ID</span>
        <span class="value" style="color: #38bdf8;">${params.incidentId}</span>
      </div>
      <div class="row">
        <span class="label">Client IP Address</span>
        <span class="value">${params.clientIp}</span>
      </div>
      <div class="row">
        <span class="label">Attack Vector Category</span>
        <span class="value" style="color: #fb923c;">${params.category}</span>
      </div>
      <div class="row">
        <span class="label">Rule Triggered</span>
        <span class="value">${params.ruleName}</span>
      </div>
      <div class="row">
        <span class="label">Strike Shield Status</span>
        <span class="value">
          <span class="strike-pill">${params.strikes >= 3 ? 'BANNED (3/3 strikes)' : `${params.strikes}/3 strikes`}</span>
        </span>
      </div>
      <div class="row">
        <span class="label">Timestamp (UTC)</span>
        <span class="value">${new Date().toISOString()}</span>
      </div>
    </div>

    <div class="footer">
      <span>Protected by</span>
      <span class="brand">OAT Security WAF Gateway &middot; v2.4 Enterprise</span>
    </div>
  </div>
</body>
</html>`;
  }

  // Public getters & management
  public getAlerts(): SecurityAlert[] {
    return this.recentAlerts;
  }

  public getRules(): WafRule[] {
    return this.rules;
  }

  public toggleRule(id: string, enabled: boolean): WafRule | null {
    const rule = this.rules.find(r => r.id === id);
    if (rule) {
      rule.enabled = enabled;
      this.saveRules();
      return rule;
    }
    return null;
  }

  public addCustomRule(ruleData: Omit<WafRule, 'id'>): WafRule {
    const id = 'RULE-CUST-' + Math.random().toString(36).substring(2, 6).toUpperCase();
    const newRule: WafRule = {
      ...ruleData,
      id
    };
    this.rules.push(newRule);
    this.saveRules();
    return newRule;
  }

  public deleteRule(id: string): boolean {
    const initial = this.rules.length;
    this.rules = this.rules.filter(r => r.id !== id);
    if (this.rules.length !== initial) {
      this.saveRules();
      return true;
    }
    return false;
  }

  public getBlacklist(): BlacklistedIp[] {
    return this.blacklist;
  }

  public getWhitelist(): WhitelistedIp[] {
    return this.whitelist;
  }

  public getStrikes(): Record<string, StrikeRecord> {
    return this.strikes;
  }

  public getSettings() {
    return this.settings;
  }

  public updateSettings(newSettings: Partial<typeof this.settings>) {
    this.settings = { ...this.settings, ...newSettings };
    this.saveAcl();
    return this.settings;
  }

  public manualBanIp(ip: string, reason: string): BlacklistedIp {
    const cleanIp = (ip || '').trim().replace(/^::ffff:/, '');
    this.blacklist = this.blacklist.filter(b => b.ip !== cleanIp);
    const banned: BlacklistedIp = {
      ip: cleanIp,
      reason: reason || 'Manual Administrator Blacklist',
      bannedAt: new Date().toISOString(),
      strikes: 3,
      country: this.guessCountry(cleanIp),
      lastUserAgent: 'Manual Control Panel'
    };
    this.blacklist.push(banned);
    if (!this.strikes[cleanIp]) {
      this.strikes[cleanIp] = {
        ip: cleanIp,
        count: 3,
        lastStrike: new Date().toISOString(),
        country: banned.country,
        incidents: [banned.reason]
      };
    } else {
      this.strikes[cleanIp].count = 3;
    }
    this.saveAcl();

    if (this.onStrikeCallback) {
      this.onStrikeCallback({ ip: cleanIp, strikes: 3, isBanned: true, reason: banned.reason });
    }
    return banned;
  }

  public unbanIp(ip: string): boolean {
    const cleanIp = (ip || '').trim().replace(/^::ffff:/, '');
    const initial = this.blacklist.length;
    this.blacklist = this.blacklist.filter(b => b.ip !== cleanIp);
    if (this.strikes[cleanIp]) {
      this.strikes[cleanIp].count = 0;
      this.strikes[cleanIp].incidents = [];
    }
    this.saveAcl();
    if (this.onStrikeCallback) {
      this.onStrikeCallback({ ip: cleanIp, strikes: 0, isBanned: false });
    }
    return this.blacklist.length !== initial;
  }

  public addToWhitelist(ip: string, description: string): WhitelistedIp {
    const cleanIp = (ip || '').trim().replace(/^::ffff:/, '');
    this.unbanIp(cleanIp);
    this.whitelist = this.whitelist.filter(w => w.ip !== cleanIp);
    const item: WhitelistedIp = {
      ip: cleanIp,
      description: description || 'Authorized IP Whitelist',
      addedAt: new Date().toISOString()
    };
    this.whitelist.push(item);
    this.saveAcl();
    return item;
  }

  public removeFromWhitelist(ip: string): boolean {
    const cleanIp = (ip || '').trim().replace(/^::ffff:/, '');
    const initial = this.whitelist.length;
    this.whitelist = this.whitelist.filter(w => w.ip !== cleanIp);
    this.saveAcl();
    return this.whitelist.length !== initial;
  }
}

export const wafEngine = new WafEngine();
