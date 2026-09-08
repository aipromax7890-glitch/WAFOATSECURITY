import React, { useState } from 'react';
import {
  Network,
  Plus,
  Server,
  ShieldCheck,
  ShieldAlert,
  Trash2,
  ExternalLink,
  Activity,
  CheckCircle2,
  Layers,
  Copy,
  Check,
  Globe,
  Gauge,
  Info
} from 'lucide-react';
import { Tenant } from '../types.ts';

interface EndpointsHealthProps {
  tenants: Tenant[];
  onAutoProvision: (data: {
    name: string;
    domain: string;
    upstream: string;
    mode?: 'BLOCKING' | 'DETECTION_ONLY';
    rateLimitPerMin?: number;
  }) => Promise<void>;
  onUpdateTenant: (id: string, updates: Partial<Tenant>) => Promise<void>;
  onDeleteTenant: (id: string) => Promise<void>;
}

export const EndpointsHealth: React.FC<EndpointsHealthProps> = ({
  tenants,
  onAutoProvision,
  onUpdateTenant,
  onDeleteTenant
}) => {
  const [showModal, setShowModal] = useState(false);
  const [name, setName] = useState('');
  const [domain, setDomain] = useState('');
  const [upstream, setUpstream] = useState('');
  const [mode, setMode] = useState<'BLOCKING' | 'DETECTION_ONLY'>('BLOCKING');
  const [rateLimit, setRateLimit] = useState(300);
  const [loading, setLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain || !upstream) return;
    setLoading(true);
    try {
      await onAutoProvision({
        name: name.trim() || domain.trim(),
        domain: domain.trim(),
        upstream: upstream.trim(),
        mode,
        rateLimitPerMin: rateLimit
      });
      setName('');
      setDomain('');
      setUpstream('');
      setShowModal(false);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleMode = (tenant: Tenant) => {
    const newMode = tenant.mode === 'BLOCKING' ? 'DETECTION_ONLY' : 'BLOCKING';
    onUpdateTenant(tenant.id, { mode: newMode });
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleAutoFillUpstream = () => {
    if (!domain) return;
    const clean = domain.trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    if (!upstream) {
      setUpstream(`http://${clean}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            Auto-Provisioning Domain &amp; Endpoints Health
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Dukungan input fleksibel (Domain atau IP:Port seperti <code>192.168.100.75:8081</code>). Perutean reverse proxy aktif seketika tanpa perlu merestart server.
          </p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-all shrink-0"
        >
          <Plus className="w-4 h-4" />
          <span>Auto-Provision Endpoint</span>
        </button>
      </div>

      {/* Tenants Grid or Empty State */}
      {tenants.length === 0 ? (
        <div className="p-10 rounded-2xl bg-slate-900/60 border border-slate-800/80 text-center flex flex-col items-center justify-center space-y-4">
          <div className="p-4 rounded-2xl bg-slate-800/80 border border-slate-700/60 text-cyan-400 shadow-inner">
            <Server className="w-8 h-8" />
          </div>
          <div className="max-w-md space-y-1.5">
            <h3 className="text-base font-semibold text-slate-100">Belum Ada Endpoint Terdaftar (Zero Dummy State)</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Sistem beroperasi murni real-time tanpa data buatan. Daftarkan domain aplikasi klien atau IP target beserta port-nya untuk mulai mengarahkan traffic melalui proteksi WAF.
            </p>
          </div>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-950/50 transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Auto-Provision Endpoint Sekarang</span>
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {tenants.map(tenant => {
            const isBlocking = tenant.mode === 'BLOCKING';
            const gatewayUrl = `${window.location.origin}/gateway/${encodeURIComponent(tenant.domain)}/`;
            const testCurlCmd = `curl -i "${window.location.origin}/gateway/${encodeURIComponent(tenant.domain)}/test?id=1'%20OR%201=1%23"`;

            return (
              <div
                key={tenant.id}
                className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex flex-col justify-between space-y-3 relative overflow-hidden"
              >
                {/* Header */}
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-cyan-400">
                        <Server className="w-4 h-4" />
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-slate-100">{tenant.name}</h3>
                        <div className="flex items-center gap-2 text-xs font-mono text-cyan-300">
                          <span>{tenant.domain}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold">
                            ONLINE
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Mode Toggle Button */}
                    <button
                      onClick={() => handleToggleMode(tenant)}
                      className={`px-2.5 py-1 rounded-full text-[10px] font-bold border transition-colors flex items-center gap-1 ${
                        isBlocking
                          ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700 hover:bg-emerald-900'
                          : 'bg-amber-950/80 text-amber-300 border-amber-700 hover:bg-amber-900'
                      }`}
                    >
                      {isBlocking ? <ShieldCheck className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />}
                      <span>{isBlocking ? 'BLOCKING MODE' : 'DETECTION ONLY'}</span>
                    </button>
                  </div>

                  {/* Upstream info */}
                  <div className="mt-3 p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1.5">
                    <div className="flex justify-between items-center text-[11px]">
                      <span className="text-slate-500">Upstream Target:</span>
                      <span className="font-mono text-slate-300 font-semibold truncate max-w-[220px]" title={tenant.upstream}>
                        {tenant.upstream}
                      </span>
                    </div>

                    <div className="flex justify-between items-center text-[11px]">
                      <span className="text-slate-500">Gateway Route:</span>
                      <div className="flex items-center gap-2">
                        <a
                          href={gatewayUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="font-mono text-cyan-400 hover:underline flex items-center gap-1 text-[11px]"
                        >
                          <span>/gateway/{tenant.domain}/</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                    </div>

                    <div className="flex justify-between items-center text-[11px]">
                      <span className="text-slate-500">Rate Limit:</span>
                      <span className="font-mono text-amber-300 font-medium">
                        {tenant.rateLimitPerMin || 300} req/min
                      </span>
                    </div>
                  </div>

                  {/* Quick Curl Test Command */}
                  <div className="mt-2 flex items-center justify-between p-1.5 rounded-md bg-slate-950/70 border border-slate-800/80 text-[10px] text-slate-400 font-mono">
                    <span className="truncate pr-2">curl .../gateway/{tenant.domain}/?id=1' OR 1=1#</span>
                    <button
                      onClick={() => handleCopy(testCurlCmd, tenant.id)}
                      className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 shrink-0 transition-colors"
                      title="Salin perintah curl uji coba serangan SQLi"
                    >
                      {copiedId === tenant.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedId === tenant.id ? 'Tersalin' : 'Copy Curl'}</span>
                    </button>
                  </div>
                </div>

                {/* Stats Footer */}
                <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-1">
                      <Activity className="w-3.5 h-3.5 text-slate-500" />
                      <span className="font-mono font-medium text-slate-200">{tenant.stats.totalRequests}</span>
                      <span className="text-[10px] text-slate-500">reqs</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
                      <span className="font-mono font-medium text-rose-400">{tenant.stats.blockedAttacks}</span>
                      <span className="text-[10px] text-slate-500">blocked</span>
                    </div>
                  </div>

                  <button
                    onClick={() => onDeleteTenant(tenant.id)}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                    title="Hapus Tenant"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Auto-Provisioning Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl bg-slate-900 border border-slate-800 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-800 text-cyan-400">
                  <Globe className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Auto-Provision Target Endpoint</h3>
                  <p className="text-[11px] text-slate-400">Tanpa restart server &amp; rute aktif instan</p>
                </div>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Nama Client / Aplikasi
                </label>
                <input
                  type="text"
                  placeholder="Contoh: Server Web Utama / DVWA Testing"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-slate-300 font-medium">
                    Domain Klien atau IP:Port Target
                  </label>
                  {domain && (
                    <button
                      type="button"
                      onClick={handleAutoFillUpstream}
                      className="text-[10px] text-cyan-400 hover:underline font-medium"
                    >
                      Gunakan untuk Upstream
                    </button>
                  )}
                </div>
                <input
                  type="text"
                  placeholder="domain.com atau 192.168.100.75:8081"
                  value={domain}
                  onChange={e => setDomain(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                  required
                />
                <p className="text-[10px] text-slate-500 mt-1">
                  Mendukung domain (misal: <code>api.example.com</code>) atau IP lokal/publik lengkap dengan port (misal: <code>192.168.100.75:8081</code>).
                </p>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Upstream Target Server URI
                </label>
                <input
                  type="text"
                  placeholder="http://192.168.100.75:8081 atau http://my-internal-app:80"
                  value={upstream}
                  onChange={e => setUpstream(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                  required
                />
                <p className="text-[10px] text-slate-500 mt-1">
                  Reverse proxy akan merutekan seluruh traffic yang lolos inspeksi WAF langsung ke target ini.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Mode Proteksi WAF
                  </label>
                  <select
                    value={mode}
                    onChange={e => setMode(e.target.value as any)}
                    className="w-full px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                  >
                    <option value="BLOCKING">BLOCKING (Blokir 403)</option>
                    <option value="DETECTION_ONLY">DETECTION ONLY (Monitor)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Rate Limit (Req/min)
                  </label>
                  <input
                    type="number"
                    value={rateLimit}
                    onChange={e => setRateLimit(Number(e.target.value))}
                    className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                    min={10}
                    max={10000}
                  />
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                >
                  Batal
                </button>
                <button
                  type="submit"
                  disabled={loading || !domain || !upstream}
                  className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50 transition-colors"
                >
                  {loading ? 'Memproses...' : 'Simpan & Aktifkan'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
