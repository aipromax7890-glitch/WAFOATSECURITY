import React, { useState } from 'react';
import {
  Skull,
  ShieldCheck,
  Zap,
  AlertOctagon,
  Plus,
  Trash2,
  RotateCcw,
  CheckCircle2,
  Lock,
  Search
} from 'lucide-react';
import { BlacklistedIp, WhitelistedIp, StrikeRecord } from '../types.ts';

interface ThreatActorsProps {
  blacklist: BlacklistedIp[];
  whitelist: WhitelistedIp[];
  strikes: Record<string, StrikeRecord>;
  onBanIp: (ip: string, reason: string) => void;
  onUnbanIp: (ip: string) => void;
  onAddToWhitelist: (ip: string, desc: string) => void;
  onRemoveFromWhitelist: (ip: string) => void;
}

export const ThreatActors: React.FC<ThreatActorsProps> = ({
  blacklist,
  whitelist,
  strikes,
  onBanIp,
  onUnbanIp,
  onAddToWhitelist,
  onRemoveFromWhitelist
}) => {
  const [newBanIp, setNewBanIp] = useState('');
  const [newBanReason, setNewBanReason] = useState('');

  const [newWhiteIp, setNewWhiteIp] = useState('');
  const [newWhiteDesc, setNewWhiteDesc] = useState('');

  const [search, setSearch] = useState('');

  // Active strikes (count between 1 and 2, not yet banned)
  const bannedIpsSet = new Set(blacklist.map(b => b.ip));
  const activeStrikesList = (Object.values(strikes) as StrikeRecord[]).filter(
    s => s.count > 0 && !bannedIpsSet.has(s.ip)
  );

  const handleManualBan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newBanIp.trim()) return;
    onBanIp(newBanIp.trim(), newBanReason.trim() || 'Manual Admin Blacklist');
    setNewBanIp('');
    setNewBanReason('');
  };

  const handleAddWhitelist = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWhiteIp.trim()) return;
    onAddToWhitelist(newWhiteIp.trim(), newWhiteDesc.trim() || 'Authorized IP Whitelist');
    setNewWhiteIp('');
    setNewWhiteDesc('');
  };

  const filteredBlacklist = blacklist.filter(b =>
    b.ip.includes(search) || b.reason.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* 3x Strike Shield Header Banner */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-red-950/40 via-slate-900 to-slate-900 border border-red-900/50 shadow-sm">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                3x Strike Shield Auto-Mitigation Engine
                <span className="px-2 py-0.5 rounded text-[10px] bg-red-950 border border-red-800 text-red-300 font-bold">
                  ACTIVE
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Every IP exhibiting 3 CRITICAL/HIGH severity attacks is automatically relegated to the ACL Blacklist in real-time.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
            <span>Threshold:</span>
            <span className="text-red-400 font-bold">3 Strikes</span>
            <span className="text-slate-600">|</span>
            <span>Penalty:</span>
            <span className="text-red-400 font-bold">Permanent 403 Ban</span>
          </div>
        </div>
      </div>

      {/* Manual Action Forms Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Manual Ban IP Card */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 mb-2 flex items-center gap-2">
            <Skull className="w-4 h-4 text-red-400" />
            Manual IP Blacklist
          </h3>
          <form onSubmit={handleManualBan} className="space-y-2.5 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Target IP Address</label>
              <input
                type="text"
                placeholder="e.g. 198.51.100.24"
                value={newBanIp}
                onChange={e => setNewBanIp(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-red-500"
                required
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Ban Reason / Forensic Note</label>
              <input
                type="text"
                placeholder="e.g. Persistent credential stuffing probe"
                value={newBanReason}
                onChange={e => setNewBanReason(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-red-500"
              />
            </div>
            <button
              type="submit"
              className="w-full py-1.5 px-3 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-xs transition-colors flex items-center justify-center gap-1.5"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Enforce Immediate Blacklist</span>
            </button>
          </form>
        </div>

        {/* Whitelist IP Card */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 mb-2 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            IP Whitelist (Bypass Inspection)
          </h3>
          <form onSubmit={handleAddWhitelist} className="space-y-2.5 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Authorized IP / Subnet</label>
              <input
                type="text"
                placeholder="e.g. 203.0.113.10 or 10.0.0.1"
                value={newWhiteIp}
                onChange={e => setNewWhiteIp(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-500"
                required
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Description</label>
              <input
                type="text"
                placeholder="e.g. Healthcheck monitor or Admin VPN"
                value={newWhiteDesc}
                onChange={e => setNewWhiteDesc(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>
            <button
              type="submit"
              className="w-full py-1.5 px-3 rounded-lg bg-emerald-700 hover:bg-emerald-600 text-white font-semibold text-xs transition-colors flex items-center justify-center gap-1.5"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Add to Trusted Whitelist</span>
            </button>
          </form>
        </div>
      </div>

      {/* Active Strike Tracker (Under Observation) */}
      <div className="p-4 rounded-xl bg-slate-900 border border-amber-900/50 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Active Strike Probes (Under Surveillance)
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-950 border border-amber-800 text-amber-300 font-bold">
              {activeStrikesList.length} IPs on Warning
            </span>
          </div>
          <p className="text-xs text-slate-500 hidden sm:block">
            IPs will be banned upon registering their 3rd strike
          </p>
        </div>

        {activeStrikesList.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {activeStrikesList.map(record => (
              <div
                key={record.ip}
                className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between text-xs space-y-2"
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-slate-200">{record.ip}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-bold">
                      Strike {record.count} / 3
                    </span>
                  </div>
                  {/* Strike progress bar */}
                  <div className="w-full h-1.5 bg-slate-800 rounded-full mt-2 overflow-hidden flex">
                    <div
                      className={`h-full ${
                        record.count === 1 ? 'w-1/3 bg-amber-400' : 'w-2/3 bg-orange-500'
                      }`}
                    />
                  </div>
                  <div className="mt-2 text-[11px] text-slate-400">
                    <span className="text-slate-500">Last Incident:</span>{' '}
                    <span className="text-rose-300 font-mono truncate block">
                      {record.incidents[record.incidents.length - 1] || 'Malicious payload probe'}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2 pt-2 border-t border-slate-850">
                  <button
                    onClick={() => onBanIp(record.ip, `Manual escalation from ${record.count} strikes`)}
                    className="flex-1 py-1 px-2 rounded bg-red-950/70 hover:bg-red-900 border border-red-800 text-red-300 text-[10px] font-medium transition-colors text-center"
                  >
                    Ban Now
                  </button>
                  <button
                    onClick={() => onUnbanIp(record.ip)}
                    className="py-1 px-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-medium transition-colors"
                  >
                    Reset
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-6 text-center text-slate-500 text-xs">
            No IPs currently on strike warning. All traffic within acceptable threshold.
          </div>
        )}
      </div>

      {/* Banned IPs Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Skull className="w-4 h-4 text-red-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Active Blacklisted IPs (Denied with 403 Forbidden)
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-950 border border-red-800 text-red-300 font-mono font-bold">
              {blacklist.length} Banned
            </span>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2 text-slate-500" />
            <input
              type="text"
              placeholder="Search banned IP..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-red-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase text-[10px] tracking-wider">
                <th className="py-2.5 px-3.5">IP Address</th>
                <th className="py-2.5 px-3">Country</th>
                <th className="py-2.5 px-3">Ban Reason</th>
                <th className="py-2.5 px-3">Strikes</th>
                <th className="py-2.5 px-3">User Agent</th>
                <th className="py-2.5 px-3">Banned At</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {filteredBlacklist.map(entry => (
                <tr key={entry.ip} className="hover:bg-slate-850/50 transition-colors">
                  <td className="py-2.5 px-3.5 font-mono text-slate-200 font-semibold whitespace-nowrap">
                    {entry.ip}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">
                      {entry.country || 'NET'}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 text-[11px] max-w-[240px] truncate">
                    {entry.reason}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 text-[10px] font-bold">
                      {entry.strikes}/3 strikes
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px] max-w-[180px] truncate">
                    {entry.lastUserAgent}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {new Date(entry.bannedAt).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
                  </td>
                  <td className="py-2.5 px-3 text-right whitespace-nowrap">
                    <button
                      onClick={() => onUnbanIp(entry.ip)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-medium transition-colors flex items-center gap-1 ml-auto"
                    >
                      <RotateCcw className="w-3 h-3 text-cyan-400" />
                      <span>Unban</span>
                    </button>
                  </td>
                </tr>
              ))}
              {filteredBlacklist.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-500 text-xs">
                    No blacklisted IPs found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Whitelist IPs Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Trusted Whitelisted IPs
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-300 font-mono font-bold">
              {whitelist.length} Allowed
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase text-[10px] tracking-wider">
                <th className="py-2.5 px-3.5">IP Address</th>
                <th className="py-2.5 px-3">Description</th>
                <th className="py-2.5 px-3">Added Date</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {whitelist.map(entry => (
                <tr key={entry.ip} className="hover:bg-slate-850/50 transition-colors">
                  <td className="py-2.5 px-3.5 font-mono text-emerald-300 font-semibold whitespace-nowrap">
                    {entry.ip}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 text-[11px]">
                    {entry.description}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {new Date(entry.addedAt).toLocaleDateString()}
                  </td>
                  <td className="py-2.5 px-3 text-right whitespace-nowrap">
                    <button
                      onClick={() => onRemoveFromWhitelist(entry.ip)}
                      className="px-2 py-1 rounded bg-slate-800 hover:bg-red-950 text-slate-300 hover:text-red-300 text-[11px] transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
              {whitelist.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-6 text-center text-slate-500 text-xs">
                    No whitelisted IPs configured.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
