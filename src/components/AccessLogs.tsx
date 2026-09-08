import React, { useState } from 'react';
import {
  FileSearch,
  Download,
  Terminal,
  Code,
  ArrowDownUp,
  RefreshCw,
  Search
} from 'lucide-react';
import { AccessLog } from '../types.ts';

interface AccessLogsProps {
  logs: AccessLog[];
}

export const AccessLogs: React.FC<AccessLogsProps> = ({ logs }) => {
  const [filterAction, setFilterAction] = useState<string>('ALL');
  const [search, setSearch] = useState('');

  // Forensic Decoder tool state
  const [encodedInput, setEncodedInput] = useState('%27%20UNION%20SELECT%20null,version()--');
  const [decodeType, setDecodeType] = useState<'url' | 'base64' | 'hex'>('url');

  const decodeString = (input: string, type: 'url' | 'base64' | 'hex'): string => {
    if (!input) return '';
    try {
      if (type === 'url') {
        let res = decodeURIComponent(input);
        try { res = decodeURIComponent(res); } catch {}
        return res;
      }
      if (type === 'base64') {
        return atob(input.trim());
      }
      if (type === 'hex') {
        const clean = input.replace(/\\x|0x|\s+/g, '');
        let str = '';
        for (let i = 0; i < clean.length; i += 2) {
          str += String.fromCharCode(parseInt(clean.substr(i, 2), 16));
        }
        return str;
      }
    } catch (err: any) {
      return `[Decoding Error: ${err.message}]`;
    }
    return input;
  };

  const filtered = logs.filter(l => {
    if (filterAction !== 'ALL' && l.wafAction !== filterAction) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        l.clientIp.includes(q) ||
        l.url.toLowerCase().includes(q) ||
        l.tenantDomain.toLowerCase().includes(q) ||
        l.userAgent.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const exportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(logs, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `oat_waf_access_logs_${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="space-y-5">
      {/* Forensic Payload Decoder Tool */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Code className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Payload Forensic Decoder Utility
            </h3>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            SOC Analyst Quick Tool
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-slate-400">Obfuscated / Encoded Input:</label>
              <div className="flex items-center gap-1">
                {(['url', 'base64', 'hex'] as const).map(t => (
                  <button
                    key={t}
                    onClick={() => setDecodeType(t)}
                    className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold transition-colors ${
                      decodeType === t
                        ? 'bg-cyan-500 text-slate-950'
                        : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
            <textarea
              value={encodedInput}
              onChange={e => setEncodedInput(e.target.value)}
              rows={2}
              className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
              placeholder="Paste encoded string or hex..."
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Normalized / Decoded Output:</label>
            <div className="w-full h-[60px] px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-emerald-400 font-mono text-xs overflow-y-auto break-all">
              {decodeString(encodedInput, decodeType)}
            </div>
          </div>
        </div>
      </div>

      {/* Access Logs Header & Filters */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm space-y-3">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <FileSearch className="w-4 h-4 text-cyan-400" />
              Gateway Access Logs &amp; Forensics
            </h2>
            <p className="text-xs text-slate-400">
              Complete chronological audit trail of all proxied and intercepted HTTP traffic.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={exportJson}
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export JSON</span>
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-2 pt-2 border-t border-slate-800 text-xs">
          <div className="relative w-full sm:w-72">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP, URL, User-Agent..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 text-xs"
            />
          </div>

          <div className="flex items-center gap-1.5 w-full sm:w-auto">
            <span className="text-slate-500 text-xs mr-1">Action:</span>
            {(['ALL', 'BLOCKED', 'BANNED', 'PASSED', 'MONITORED'] as const).map(action => (
              <button
                key={action}
                onClick={() => setFilterAction(action)}
                className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                  filterAction === action
                    ? 'bg-slate-800 text-white font-bold border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {action}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase text-[10px] tracking-wider">
                <th className="py-2.5 px-3.5">Status</th>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">IP Address</th>
                <th className="py-2.5 px-3">Method &amp; Path</th>
                <th className="py-2.5 px-3">Domain</th>
                <th className="py-2.5 px-3">WAF Action</th>
                <th className="py-2.5 px-3">Latency</th>
                <th className="py-2.5 px-3 text-right">User Agent</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {filtered.map(log => (
                <tr key={log.id} className="hover:bg-slate-850/50 transition-colors">
                  <td className="py-2.5 px-3.5 whitespace-nowrap">
                    <span
                      className={`font-mono font-bold px-1.5 py-0.5 rounded text-[10px] ${
                        log.status === 200
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : log.status === 403
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}
                    >
                      {log.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-200 whitespace-nowrap">
                    {log.clientIp}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 font-mono text-[11px] max-w-[200px] truncate">
                    <span className="font-bold text-cyan-400 mr-1">{log.method}</span>
                    {log.url}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {log.tenantDomain}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        log.wafAction === 'BLOCKED' || log.wafAction === 'BANNED'
                          ? 'bg-red-950 text-red-300 border border-red-800'
                          : log.wafAction === 'MONITORED'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      }`}
                    >
                      {log.wafAction}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {log.durationMs}ms
                  </td>
                  <td className="py-2.5 px-3 text-slate-500 font-mono text-[10px] text-right truncate max-w-[160px]">
                    {log.userAgent}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 text-xs">
                    No access log records recorded yet.
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
