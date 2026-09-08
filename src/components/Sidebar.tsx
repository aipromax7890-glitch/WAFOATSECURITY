import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Skull,
  Network,
  FileSearch,
  Sliders,
  Bot,
  Activity,
  Lock
} from 'lucide-react';
import { SocTab } from '../types.ts';

interface SidebarProps {
  activeTab: SocTab;
  setActiveTab: (tab: SocTab) => void;
  alertCount: number;
  strikeCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  alertCount,
  strikeCount
}) => {
  const menuItems = [
    {
      id: 'overview' as SocTab,
      label: 'Live Overview',
      icon: LayoutDashboard,
      badge: null
    },
    {
      id: 'alerts' as SocTab,
      label: 'Security Alerts',
      icon: ShieldAlert,
      badge: alertCount > 0 ? alertCount : null,
      badgeColor: 'bg-red-500/20 text-red-400 border-red-500/30'
    },
    {
      id: 'threats' as SocTab,
      label: 'Threat Actors & ACL',
      icon: Skull,
      badge: strikeCount > 0 ? `${strikeCount} strikes` : null,
      badgeColor: 'bg-amber-500/20 text-amber-400 border-amber-500/30'
    },
    {
      id: 'tenants' as SocTab,
      label: 'Endpoints & Tenants',
      icon: Network,
      badge: null
    },
    {
      id: 'logs' as SocTab,
      label: 'Access Logs & Forensic',
      icon: FileSearch,
      badge: null
    },
    {
      id: 'control' as SocTab,
      label: 'WAF Rules & Policy',
      icon: Sliders,
      badge: null
    },
    {
      id: 'copilot' as SocTab,
      label: 'AI SOC Copilot',
      icon: Bot,
      badge: 'Gemini AI',
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/30'
    }
  ];

  return (
    <aside className="w-full lg:w-64 bg-slate-950 border-b lg:border-b-0 lg:border-r border-slate-800 flex flex-col justify-between shrink-0 p-3">
      <nav className="space-y-1">
        <div className="px-3 py-1.5 text-[11px] font-bold uppercase tracking-wider text-slate-500">
          SOC Navigation
        </div>
        {menuItems.map(item => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2.5 truncate">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span className="truncate">{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                    item.badgeColor || 'bg-slate-800 text-slate-300 border-slate-700'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Engine Status Card */}
      <div className="hidden lg:block mt-6 p-3 rounded-xl bg-gradient-to-b from-slate-900 to-slate-950 border border-slate-800 text-xs">
        <div className="flex items-center gap-2 mb-2">
          <Lock className="w-3.5 h-3.5 text-emerald-400" />
          <span className="font-semibold text-slate-200">WAF Active Shield</span>
        </div>
        <div className="space-y-1 text-[11px] text-slate-400">
          <div className="flex justify-between">
            <span>Inspection Engine:</span>
            <span className="text-emerald-400 font-mono">Real-time</span>
          </div>
          <div className="flex justify-between">
            <span>Auto-Ban Threshold:</span>
            <span className="text-red-400 font-mono">3x Strikes</span>
          </div>
          <div className="flex justify-between">
            <span>Reverse Proxy:</span>
            <span className="text-cyan-400 font-mono">Port 3000</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
