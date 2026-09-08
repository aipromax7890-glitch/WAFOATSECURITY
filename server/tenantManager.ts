import fs from 'fs';
import path from 'path';

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

const DATA_DIR = path.join(process.cwd(), 'data');
const TENANTS_FILE = path.join(DATA_DIR, 'tenants.json');

/**
 * Normalizes client domain / host identifier.
 * Strips protocol and path, but preserves port if provided (e.g. 192.168.100.75:8081 or domain.com).
 */
export function normalizeDomain(input: string): string {
  if (!input) return '';
  let cleaned = input.trim().toLowerCase();
  // Remove protocol
  cleaned = cleaned.replace(/^https?:\/\//i, '');
  // Remove path and query string if user pasted a full URL
  cleaned = cleaned.split('/')[0].split('?')[0].split('#')[0];
  return cleaned;
}

/**
 * Normalizes upstream target URI.
 * Guarantees protocol (default http://) and removes trailing slashes.
 */
export function normalizeUpstream(input: string): string {
  if (!input) return '';
  let cleaned = input.trim();
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = 'http://' + cleaned;
  }
  cleaned = cleaned.replace(/\/+$/, '');
  return cleaned;
}

class TenantManager {
  private tenants: Tenant[] = [];

  constructor() {
    this.init();
  }

  private init() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      if (fs.existsSync(TENANTS_FILE)) {
        const raw = fs.readFileSync(TENANTS_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        this.tenants = parsed.tenants || [];
      } else {
        // Zero dummy data requirement: clean initial state (0)
        this.tenants = [];
        this.save();
      }
    } catch (err) {
      console.error('Failed to load tenants.json:', err);
      this.tenants = [];
    }
  }

  public save() {
    try {
      fs.writeFileSync(TENANTS_FILE, JSON.stringify({ tenants: this.tenants }, null, 2), 'utf-8');
    } catch (err) {
      console.error('Failed to save tenants:', err);
    }
  }

  public getAll(): Tenant[] {
    return this.tenants;
  }

  public getById(id: string): Tenant | undefined {
    if (!id) return undefined;
    return this.tenants.find(t => t.id === id);
  }

  /**
   * Flexible host/domain resolver matching:
   * 1. Exact match with port (e.g. 192.168.100.75:8081)
   * 2. Host-only match (e.g. 192.168.100.75 matching 192.168.100.75:8081)
   * 3. Subdomain match (e.g. api.example.com matching example.com)
   * 4. Upstream host match (e.g. matching upstream URL host)
   */
  public getByDomain(hostOrDomain: string): Tenant | undefined {
    if (!hostOrDomain) return undefined;
    const cleanHost = normalizeDomain(hostOrDomain);
    const hostWithoutPort = cleanHost.split(':')[0];

    // 1. Exact match
    const exact = this.tenants.find(t => t.domain.toLowerCase() === cleanHost);
    if (exact) return exact;

    // 2. Match without port or vice versa
    const hostMatch = this.tenants.find(t => {
      const tenantHost = t.domain.split(':')[0].toLowerCase();
      return tenantHost === hostWithoutPort || hostWithoutPort.endsWith('.' + tenantHost);
    });
    if (hostMatch) return hostMatch;

    // 3. Match against upstream target host or URL
    const upstreamMatch = this.tenants.find(t => {
      try {
        const url = new URL(t.upstream);
        const upHost = url.host.toLowerCase();
        const upHostname = url.hostname.toLowerCase();
        return upHost === cleanHost || upHostname === hostWithoutPort;
      } catch {
        return false;
      }
    });
    if (upstreamMatch) return upstreamMatch;

    return undefined;
  }

  public autoProvision(data: {
    name: string;
    domain: string;
    upstream: string;
    mode?: 'BLOCKING' | 'DETECTION_ONLY';
    rateLimitPerMin?: number;
  }): Tenant {
    const cleanDomain = normalizeDomain(data.domain);
    const cleanUpstream = normalizeUpstream(data.upstream);

    const id = 'tenant-' + Date.now().toString(36) + '-' + Math.random().toString(36).substring(2, 6);
    const newTenant: Tenant = {
      id,
      name: data.name ? data.name.trim() : cleanDomain,
      domain: cleanDomain,
      upstream: cleanUpstream,
      mode: data.mode || 'BLOCKING',
      createdAt: new Date().toISOString(),
      status: 'active',
      rateLimitPerMin: Number(data.rateLimitPerMin) || 300,
      stats: {
        totalRequests: 0,
        blockedAttacks: 0,
        bandwidthBytes: 0
      }
    };

    // Remove existing if domain conflicts to update dynamically
    this.tenants = this.tenants.filter(t => t.domain !== newTenant.domain);
    this.tenants.push(newTenant);
    this.save();
    return newTenant;
  }

  public updateTenant(id: string, updates: Partial<Tenant>): Tenant | null {
    const idx = this.tenants.findIndex(t => t.id === id);
    if (idx === -1) return null;

    if (updates.domain) {
      updates.domain = normalizeDomain(updates.domain);
    }
    if (updates.upstream) {
      updates.upstream = normalizeUpstream(updates.upstream);
    }

    this.tenants[idx] = {
      ...this.tenants[idx],
      ...updates,
      id // preserve ID
    };
    this.save();
    return this.tenants[idx];
  }

  public deleteTenant(id: string): boolean {
    const initialLen = this.tenants.length;
    this.tenants = this.tenants.filter(t => t.id !== id);
    if (this.tenants.length !== initialLen) {
      this.save();
      return true;
    }
    return false;
  }

  public clearAll() {
    this.tenants = [];
    this.save();
  }

  public recordRequest(tenantId: string, isAttack: boolean, bytes: number = 350) {
    const tenant = this.tenants.find(t => t.id === tenantId);
    if (tenant) {
      tenant.stats.totalRequests += 1;
      if (isAttack) {
        tenant.stats.blockedAttacks += 1;
      }
      tenant.stats.bandwidthBytes += bytes;
      this.save();
    }
  }
}

export const tenantManager = new TenantManager();
