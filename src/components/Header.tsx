import React from 'react';
import { Shield, Radio, Activity, AlertTriangle, Network } from 'lucide-react';
import { SocTab } from '../types.ts';

interface HeaderProps {
  activeTab: SocTab;
  setActiveTab: (tab: SocTab) => void;
  isConnected: boolean;
  bannedCount: number;
  strikeCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  isConnected,
  bannedCount,
  strikeCount
}) => {
  return (
    <header className="bg-slate-950 border-b border-slate-800 text-white px-5 py-3 sticky top-0 z-40 shadow-lg shadow-black/40">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        {/* Brand & Platform Identity */}
        <div className="flex items-center gap-3.5">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 text-cyan-400 shadow-inner">
            <Shield className="w-5 h-5" />
            <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping opacity-75" />
            <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-emerald-500" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                OAT Security
              </h1>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-500/30 text-cyan-400">
                Cloud WAF &middot; SOC
              </span>
              <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 hidden sm:inline-block">
                Multi-Tenant Gateway
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Universal Reverse Proxy &bull; 3x Strike Shield &bull; Zero-Day Payload Inspection
            </p>
          </div>
        </div>

        {/* Real-time Status Badges & Quick Action */}
        <div className="flex items-center gap-2.5 w-full md:w-auto justify-between md:justify-end">
          {/* Socket.io Indicator */}
          <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs">
            <Radio className={`w-3.5 h-3.5 ${isConnected ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
            <span className="text-slate-300 font-medium">
              {isConnected ? 'SOC Push Live' : 'Connecting...'}
            </span>
          </div>

          {/* Strikes / Bans badge */}
          <div className="hidden lg:flex items-center gap-2 px-3 py-1 rounded-lg bg-red-950/40 border border-red-900/50 text-xs">
            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
            <span className="text-red-300 font-medium">
              {bannedCount} Banned IPs
            </span>
            {strikeCount > 0 && (
              <span className="px-1.5 py-0.2 rounded bg-red-900 text-[10px] text-red-200 font-bold">
                {strikeCount} Active Strikes
              </span>
            )}
          </div>

          {/* Quick Endpoints Navigation Trigger */}
          <button
            onClick={() => setActiveTab('tenants')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shadow-sm ${
              activeTab === 'tenants'
                ? 'bg-cyan-500 text-slate-950 ring-2 ring-cyan-400'
                : 'bg-cyan-600/90 hover:bg-cyan-500 text-white'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Endpoints &amp; Tenants</span>
          </button>
        </div>
      </div>
    </header>
  );
};
