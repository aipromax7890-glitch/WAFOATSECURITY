import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Bot,
  Skull,
  FileCode,
  ExternalLink,
  ChevronRight,
  AlertTriangle
} from 'lucide-react';
import { SecurityAlert } from '../types.ts';

interface SecurityAlertsProps {
  alerts: SecurityAlert[];
  onSelectAlert: (alert: SecurityAlert) => void;
  onAnalyzeAi: (alert: SecurityAlert) => void;
  onBanIp: (ip: string, reason: string) => void;
}

export const SecurityAlerts: React.FC<SecurityAlertsProps> = ({
  alerts,
  onSelectAlert,
  onAnalyzeAi,
  onBanIp
}) => {
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  const filtered = alerts.filter(a => {
    if (selectedCategory !== 'ALL' && a.category.toLowerCase() !== selectedCategory.toLowerCase()) {
      return false;
    }
    if (selectedSeverity !== 'ALL' && a.severity !== selectedSeverity) {
      return false;
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        a.clientIp.includes(q) ||
        a.ruleName.toLowerCase().includes(q) ||
        a.url.toLowerCase().includes(q) ||
        a.matchedSnippet.toLowerCase().includes(q) ||
        a.tenantDomain.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Header & Filter Controls */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm space-y-3">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Security Alerts Forensics Feed
            </h2>
            <p className="text-xs text-slate-400">
              Live intercepted threat payloads with regex pattern matching and auto-mitigation strikes.
            </p>
          </div>
          <span className="text-xs px-2.5 py-1 rounded-full bg-slate-800 border border-slate-700 text-slate-300 font-mono">
            {filtered.length} of {alerts.length} Incidents
          </span>
        </div>

        {/* Filter bar */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-800 text-xs">
          {/* Search box */}
          <div className="relative sm:col-span-2">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP, URL, snippet, rule..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 text-xs"
            />
          </div>

          {/* Category filter */}
          <div>
            <select
              value={selectedCategory}
              onChange={e => setSelectedCategory(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
            >
              <option value="ALL">All Threat Categories</option>
              <option value="SQLi">SQL Injection (SQLi)</option>
              <option value="XSS">Cross-Site Scripting (XSS)</option>
              <option value="LFI">Path Traversal / LFI</option>
              <option value="RCE">Remote Code Execution (RCE)</option>
              <option value="Malware">Malware / Web Shell</option>
              <option value="CSRF">CSRF</option>
            </select>
          </div>

          {/* Severity filter */}
          <div>
            <select
              value={selectedSeverity}
              onChange={e => setSelectedSeverity(e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase text-[10px] tracking-wider">
                <th className="py-3 px-3.5">Severity</th>
                <th className="py-3 px-3">Time</th>
                <th className="py-3 px-3">Attacker IP</th>
                <th className="py-3 px-3">Target Endpoint</th>
                <th className="py-3 px-3">Rule &amp; Signature</th>
                <th className="py-3 px-3">Payload Snippet</th>
                <th className="py-3 px-3">Strike Shield</th>
                <th className="py-3 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {filtered.map(alert => (
                <tr key={alert.id} className="hover:bg-slate-850/60 transition-colors">
                  {/* Severity */}
                  <td className="py-2.5 px-3.5 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        alert.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : alert.severity === 'HIGH'
                          ? 'bg-orange-950 text-orange-300 border border-orange-800'
                          : alert.severity === 'MEDIUM'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-blue-950 text-blue-300 border border-blue-800'
                      }`}
                    >
                      {alert.severity}
                    </span>
                  </td>

                  {/* Time */}
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </td>

                  {/* Attacker IP */}
                  <td className="py-2.5 px-3 font-mono text-slate-200 whitespace-nowrap">
                    <span className="inline-block px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] mr-1.5">
                      {alert.country || 'NET'}
                    </span>
                    {alert.clientIp}
                  </td>

                  {/* Target Endpoint */}
                  <td className="py-2.5 px-3 text-slate-300 font-mono text-[11px] max-w-[180px]">
                    <div className="truncate font-semibold text-slate-200">{alert.tenantDomain}</div>
                    <div className="truncate text-slate-500 text-[10px]">
                      {alert.method} {alert.url}
                    </div>
                  </td>

                  {/* Rule & Category */}
                  <td className="py-2.5 px-3 max-w-[200px]">
                    <div className="font-medium text-slate-200 truncate">{alert.ruleName}</div>
                    <div className="flex items-center gap-1.5 text-[10px] text-slate-400 mt-0.5">
                      <span className="font-bold text-cyan-400">{alert.category}</span>
                      <span>&bull;</span>
                      <span className="text-slate-500">in {alert.matchedTarget}</span>
                    </div>
                  </td>

                  {/* Payload Snippet */}
                  <td className="py-2.5 px-3 font-mono text-[11px] text-rose-300 max-w-[220px]">
                    <div className="bg-slate-950 p-1 rounded border border-slate-800 truncate" title={alert.matchedSnippet}>
                      <code>{alert.matchedSnippet}</code>
                    </div>
                  </td>

                  {/* Strike Shield */}
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    {alert.isBanned || alert.strikes >= 3 ? (
                      <span className="px-2 py-0.5 rounded bg-red-900/60 border border-red-700 text-red-200 text-[10px] font-bold flex items-center gap-1 w-fit">
                        <Skull className="w-3 h-3 text-red-400" />
                        BANNED (3/3)
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300 text-[10px] font-semibold">
                        Strike: {alert.strikes}/3
                      </span>
                    )}
                  </td>

                  {/* Actions */}
                  <td className="py-2.5 px-3 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-1.5">
                      {/* AI Analyze Button */}
                      <button
                        onClick={() => onAnalyzeAi(alert)}
                        title="Analyze incident with Gemini AI"
                        className="px-2 py-1 rounded bg-purple-950/60 hover:bg-purple-900 border border-purple-800/80 text-purple-300 text-[10px] font-semibold flex items-center gap-1 transition-colors"
                      >
                        <Bot className="w-3 h-3" />
                        <span>AI</span>
                      </button>

                      {/* Inspect details */}
                      <button
                        onClick={() => onSelectAlert(alert)}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[10px] font-medium transition-colors"
                      >
                        Forensic
                      </button>

                      {/* Ban IP */}
                      {!alert.isBanned && (
                        <button
                          onClick={() => onBanIp(alert.clientIp, `Manual ban from Alert ${alert.id}`)}
                          className="px-2 py-1 rounded bg-red-950/60 hover:bg-red-900 border border-red-800 text-red-300 text-[10px] font-medium transition-colors"
                        >
                          Ban IP
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 text-xs">
                    No security alerts found matching your criteria.
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
