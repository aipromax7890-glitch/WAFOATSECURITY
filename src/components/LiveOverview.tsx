import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Globe,
  Skull,
  Activity,
  ArrowUpRight,
  Clock
} from 'lucide-react';
import { OverviewStats, SecurityAlert, SocTab } from '../types.ts';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface LiveOverviewProps {
  stats: OverviewStats | null;
  recentAlerts: SecurityAlert[];
  setActiveTab: (tab: SocTab) => void;
  onSelectAlert: (alert: SecurityAlert) => void;
}

export const LiveOverview: React.FC<LiveOverviewProps> = ({
  stats,
  recentAlerts,
  setActiveTab,
  onSelectAlert
}) => {
  const totalRequests = stats?.totalRequests || 0;
  const totalBlocked = stats?.totalBlocked || 0;
  const mitigationRate = totalRequests > 0 ? ((totalBlocked / totalRequests) * 100).toFixed(1) : '0.0';

  // Line Chart Data
  const lineLabels = stats?.recentRate.map(r => r.time) || [];
  const lineTotal = stats?.recentRate.map(r => r.count) || [];
  const lineBlocked = stats?.recentRate.map(r => r.blocked) || [];

  const lineChartData = {
    labels: lineLabels.length > 0 ? lineLabels : ['Standby'],
    datasets: [
      {
        label: 'Total Traffic',
        data: lineTotal.length > 0 ? lineTotal : [0],
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56, 189, 248, 0.1)',
        fill: true,
        tension: 0.35,
        pointRadius: 3,
        pointBackgroundColor: '#38bdf8'
      },
      {
        label: 'Blocked Attacks (WAF 403)',
        data: lineBlocked.length > 0 ? lineBlocked : [0],
        borderColor: '#f43f5e',
        backgroundColor: 'rgba(244, 63, 94, 0.15)',
        fill: true,
        tension: 0.35,
        pointRadius: 4,
        pointBackgroundColor: '#f43f5e'
      }
    ]
  };

  const lineChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: '#94a3b8',
          font: { size: 11 }
        }
      },
      tooltip: {
        backgroundColor: '#0f172a',
        borderColor: '#334155',
        borderWidth: 1,
        titleColor: '#f8fafc',
        bodyColor: '#cbd5e1'
      }
    },
    scales: {
      x: {
        grid: { color: 'rgba(51, 65, 85, 0.3)' },
        ticks: { color: '#64748b', font: { size: 10 } }
      },
      y: {
        grid: { color: 'rgba(51, 65, 85, 0.3)' },
        ticks: { color: '#64748b', font: { size: 10 } },
        beginAtZero: true
      }
    }
  };

  // Donut Chart Data
  const cat = stats?.categoryDistribution || { SQLi: 0, XSS: 0, LFI: 0, RCE: 0, Malware: 0, CSRF: 0 };
  const donutLabels = Object.keys(cat);
  const donutValues = Object.values(cat);

  const donutChartData = {
    labels: donutLabels,
    datasets: [
      {
        data: donutValues,
        backgroundColor: [
          '#ef4444', // SQLi - red
          '#f97316', // XSS - orange
          '#eab308', // LFI - yellow
          '#8b5cf6', // RCE - purple
          '#ec4899', // Malware - pink
          '#06b6d4', // CSRF - cyan
          '#64748b'  // Other - slate
        ],
        borderWidth: 2,
        borderColor: '#0f172a'
      }
    ]
  };

  const donutChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
        labels: {
          color: '#cbd5e1',
          font: { size: 11 },
          boxWidth: 12
        }
      }
    },
    cutout: '70%'
  };

  return (
    <div className="space-y-5">
      {/* Top Banner & WAF Gateway Real-Time Status */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-md">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              Universal Reverse Proxy Active &amp; Protecting Endpoints
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            </h2>
            <p className="text-xs text-slate-400">
              Real-time Layer-7 inspection enabled. Payloads across URL, Query, Headers, and Body are inspected against active WAF rules.
            </p>
          </div>
        </div>
        <button
          onClick={() => setActiveTab('alerts')}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold transition-all shrink-0"
        >
          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          <span>View Alerts Log</span>
          <ArrowUpRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Inspected */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1.5">
            <span>Inspected</span>
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white tracking-tight">
            {totalRequests.toLocaleString()}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Total HTTP requests</div>
        </div>

        {/* Blocked Attacks */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-red-950/60 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1.5">
            <span>Blocked (403)</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-400 tracking-tight">
            {totalBlocked.toLocaleString()}
          </div>
          <div className="text-[10px] text-rose-400/80 mt-1">Mitigation: {mitigationRate}%</div>
        </div>

        {/* Banned IPs */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1.5">
            <span>Banned IPs</span>
            <Skull className="w-3.5 h-3.5 text-red-500" />
          </div>
          <div className="text-xl font-bold font-mono text-white tracking-tight">
            {stats?.bannedIpCount || 0}
          </div>
          <div className="text-[10px] text-red-400/90 mt-1">3x Strike ACL blacklist</div>
        </div>

        {/* Active Strikes */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1.5">
            <span>Active Strikes</span>
            <Zap className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-300 tracking-tight">
            {stats?.activeStrikesCount || 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Threshold: 3 strikes</div>
        </div>

        {/* Protected Tenants */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1.5">
            <span>Tenants</span>
            <Globe className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white tracking-tight">
            {stats?.tenantCount || 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Upstream backends</div>
        </div>

        {/* WAF Latency */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1.5">
            <span>Latency</span>
            <Clock className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400 tracking-tight">
            {stats?.averageLatencyMs || '0.00ms'}
          </div>
          <div className="text-[10px] text-emerald-400/80 mt-1">Inspection overhead</div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Real-time Attack Timeline */}
        <div className="lg:col-span-2 p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Real-Time Traffic &amp; Threat Rate
              </h3>
              <p className="text-[11px] text-slate-500">Live request inspection timeline over rolling window</p>
            </div>
            <div className="flex items-center gap-2 text-[10px] text-slate-400">
              <span className="w-2 h-2 rounded-full bg-cyan-400" /> Total
              <span className="w-2 h-2 rounded-full bg-rose-500 ml-2" /> Blocked Attacks
            </div>
          </div>
          <div className="h-60">
            <Line data={lineChartData} options={lineChartOptions} />
          </div>
        </div>

        {/* Attack Vector Distribution Donut */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex flex-col justify-between">
          <div className="mb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Threat Vectors (OWASP Top 10)
            </h3>
            <p className="text-[11px] text-slate-500">Categorical distribution of neutralized attacks</p>
          </div>
          <div className="h-48 flex items-center justify-center relative my-auto">
            <Doughnut data={donutChartData} options={donutChartOptions} />
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none pr-14">
              <span className="text-xs text-slate-400 font-medium">Mitigated</span>
              <span className="text-lg font-bold font-mono text-white">{totalBlocked}</span>
            </div>
          </div>
          <div className="text-[11px] text-slate-500 text-center pt-2 border-t border-slate-800">
            Engine active: SQLi, XSS, LFI, RCE, CSRF, Malware
          </div>
        </div>
      </div>

      {/* Recent Alerts Feed Table */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Live Security Incidents Feed
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-rose-950/70 border border-rose-900 text-rose-400 font-bold animate-pulse">
              LIVE
            </span>
          </div>
          <button
            onClick={() => setActiveTab('alerts')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
          >
            <span>View All Alerts</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 uppercase text-[10px] tracking-wider">
                <th className="pb-2">Timestamp</th>
                <th className="pb-2">Attacker IP</th>
                <th className="pb-2">Vector</th>
                <th className="pb-2">Target Domain</th>
                <th className="pb-2">Matched Payload Snippet</th>
                <th className="pb-2">Action</th>
                <th className="pb-2 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {recentAlerts.slice(0, 5).map(alert => (
                <tr key={alert.id} className="hover:bg-slate-850/50 transition-colors">
                  <td className="py-2.5 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 font-mono text-slate-200 whitespace-nowrap">
                    <span className="inline-block px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] mr-1.5">
                      {alert.country || 'NET'}
                    </span>
                    {alert.clientIp}
                  </td>
                  <td className="py-2.5 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                        alert.category === 'SQLi'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : alert.category === 'XSS'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : alert.category === 'RCE'
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                          : alert.category === 'LFI'
                          ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                          : 'bg-pink-500/20 text-pink-400 border border-pink-500/30'
                      }`}
                    >
                      {alert.category}
                    </span>
                  </td>
                  <td className="py-2.5 text-slate-300 font-mono text-[11px] truncate max-w-[140px]">
                    {alert.tenantDomain}
                  </td>
                  <td className="py-2.5 font-mono text-[11px] text-rose-300 truncate max-w-[240px]">
                    <code>{alert.matchedSnippet}</code>
                  </td>
                  <td className="py-2.5 whitespace-nowrap">
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                        alert.action === 'BLOCKED'
                          ? 'bg-red-950 text-red-300 border border-red-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}
                    >
                      {alert.action} (403)
                    </span>
                  </td>
                  <td className="py-2.5 text-right whitespace-nowrap">
                    <button
                      onClick={() => onSelectAlert(alert)}
                      className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition-colors"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
              {recentAlerts.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-500 text-xs">
                    No security alerts recorded yet. Send live attack traffic to the gateway to trigger real-time detection.
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
