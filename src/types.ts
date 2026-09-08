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
  category: 'SQLi' | 'XSS' | 'LFI' | 'RCE' | 'CSRF' | 'Malware' | string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  matchedTarget: 'URL' | 'QUERY' | 'HEADER' | 'BODY';
  matchedSnippet: string;
  action: 'BLOCKED' | 'MONITORED';
  userAgent: string;
  country: string;
  strikes: number;
  isBanned: boolean;
}

export interface Tenant {
  id: string;
  name: string;
  domain: string;
  upstream: string;
  mode: 'BLOCKING' | 'DETECTION_ONLY';
  createdAt: string;
  status: 'active' | 'maintenance' | 'offline';
  rateLimitPerMin: number;
  stats: {
    totalRequests: number;
    blockedAttacks: number;
    bandwidthBytes: number;
  };
}

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

export interface OverviewStats {
  totalRequests: number;
  totalBlocked: number;
  bannedIpCount: number;
  activeStrikesCount: number;
  tenantCount: number;
  activeRulesCount: number;
  categoryDistribution: Record<string, number>;
  recentRate: Array<{ time: string; count: number; blocked: number }>;
  averageLatencyMs?: string;
}

export interface AccessLog {
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

export type SocTab =
  | 'overview'
  | 'alerts'
  | 'threats'
  | 'tenants'
  | 'logs'
  | 'control'
  | 'copilot';
