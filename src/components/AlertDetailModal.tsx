import React from 'react';
import {
  ShieldAlert,
  X,
  Bot,
  Skull,
  ShieldCheck,
  Copy,
  ExternalLink,
  Code
} from 'lucide-react';
import { SecurityAlert } from '../types.ts';

interface AlertDetailModalProps {
  alert: SecurityAlert | null;
  onClose: () => void;
  onAnalyzeAi: (alert: SecurityAlert) => void;
  onBanIp: (ip: string, reason: string) => void;
  onWhitelistIp: (ip: string, desc: string) => void;
}

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({
  alert,
  onClose,
  onAnalyzeAi,
  onBanIp,
  onWhitelistIp
}) => {
  if (!alert) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-5 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-rose-500/20 border border-rose-500/40 text-rose-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Incident Forensics: {alert.id}
              </h3>
              <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
                <span className="font-semibold text-rose-400">{alert.category} Threat</span>
                <span>&bull;</span>
                <span className="font-mono">{alert.tenantDomain}</span>
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Fields */}
        <div className="space-y-3 text-xs">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Severity</span>
              <span
                className={`font-bold text-xs ${
                  alert.severity === 'CRITICAL'
                    ? 'text-red-400'
                    : alert.severity === 'HIGH'
                    ? 'text-orange-400'
                    : 'text-amber-400'
                }`}
              >
                {alert.severity}
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Action Taken</span>
              <span className="font-bold text-xs text-emerald-400 font-mono">
                {alert.action} (403 Forbidden)
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 text-[10px] block">3x Strike Status</span>
              <span className="font-bold text-xs text-amber-300 font-mono">
                {alert.isBanned || alert.strikes >= 3 ? 'BANNED (3/3)' : `Strike ${alert.strikes} of 3`}
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Source IP &amp; Origin</span>
              <span className="font-mono text-slate-200 font-semibold">
                {alert.clientIp} ({alert.country || 'NET'})
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 text-[10px] block">HTTP Method &amp; Target</span>
              <span className="font-mono text-slate-200">
                {alert.method} {alert.matchedTarget}
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-slate-500 text-[10px] block">Detection Rule</span>
              <span className="font-medium text-slate-200 truncate block" title={alert.ruleName}>
                {alert.ruleName}
              </span>
            </div>
          </div>

          {/* Full Target URL */}
          <div>
            <label className="block text-slate-400 text-[11px] mb-1 font-medium">
              Requested URL &amp; Path:
            </label>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 break-all">
              {alert.url}
            </div>
          </div>

          {/* Matched Payload Box */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-slate-400 text-[11px] font-medium flex items-center gap-1.5">
                <Code className="w-3.5 h-3.5 text-rose-400" />
                <span>Triggered Threat Payload Signature:</span>
              </label>
              <button
                onClick={() => handleCopy(alert.matchedSnippet)}
                className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <Copy className="w-3 h-3" />
                <span>Copy Payload</span>
              </button>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-red-900/60 font-mono text-xs text-rose-300 break-all">
              <code>{alert.matchedSnippet}</code>
            </div>
          </div>

          {/* User-Agent */}
          <div>
            <label className="block text-slate-500 text-[10px] mb-1">Client User-Agent:</label>
            <div className="p-2 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-400 truncate">
              {alert.userAgent}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            {!alert.isBanned && (
              <button
                onClick={() => {
                  onBanIp(alert.clientIp, `Forensic escalation: ${alert.category}`);
                  onClose();
                }}
                className="px-3 py-1.5 rounded-lg bg-red-950 hover:bg-red-900 border border-red-800 text-red-300 text-xs font-semibold flex items-center gap-1.5 transition-colors"
              >
                <Skull className="w-3.5 h-3.5" />
                <span>Enforce Ban</span>
              </button>
            )}

            <button
              onClick={() => {
                onWhitelistIp(alert.clientIp, `Whitelisted from Alert ${alert.id}`);
                onClose();
              }}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium flex items-center gap-1.5 transition-colors"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Whitelist IP</span>
            </button>
          </div>

          <button
            onClick={() => {
              onAnalyzeAi(alert);
              onClose();
            }}
            className="px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-colors"
          >
            <Bot className="w-4 h-4" />
            <span>Analyze with Gemini AI</span>
          </button>
        </div>
      </div>
    </div>
  );
};
