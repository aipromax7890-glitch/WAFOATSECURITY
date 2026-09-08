import React, { useState, useEffect } from 'react';
import { io, Socket } from 'socket.io-client';
import {
  SecurityAlert,
  Tenant,
  WafRule,
  BlacklistedIp,
  WhitelistedIp,
  StrikeRecord,
  OverviewStats,
  AccessLog,
  SocTab
} from './types.ts';

import { Header } from './components/Header.tsx';
import { Sidebar } from './components/Sidebar.tsx';
import { LiveOverview } from './components/LiveOverview.tsx';
import { SecurityAlerts } from './components/SecurityAlerts.tsx';
import { ThreatActors } from './components/ThreatActors.tsx';
import { EndpointsHealth } from './components/EndpointsHealth.tsx';
import { AccessLogs } from './components/AccessLogs.tsx';
import { ControlPanel } from './components/ControlPanel.tsx';
import { AiAssistant } from './components/AiAssistant.tsx';
import { AlertDetailModal } from './components/AlertDetailModal.tsx';

export function App() {
  const [activeTab, setActiveTab] = useState<SocTab>('overview');
  const [isConnected, setIsConnected] = useState(false);

  // Core Data States
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [blacklist, setBlacklist] = useState<BlacklistedIp[]>([]);
  const [whitelist, setWhitelist] = useState<WhitelistedIp[]>([]);
  const [strikes, setStrikes] = useState<Record<string, StrikeRecord>>({});
  const [rules, setRules] = useState<WafRule[]>([]);
  const [logs, setLogs] = useState<AccessLog[]>([]);

  // Modals & Selected items
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [copilotAlert, setCopilotAlert] = useState<SecurityAlert | null>(null);

  // Fetch all initial data from server API
  const refreshData = async () => {
    try {
      const [
        statsRes,
        alertsRes,
        tenantsRes,
        blackRes,
        whiteRes,
        strikesRes,
        rulesRes,
        logsRes
      ] = await Promise.all([
        fetch('/api/stats').then(r => r.json()),
        fetch('/api/alerts').then(r => r.json()),
        fetch('/api/tenants').then(r => r.json()),
        fetch('/api/acl/blacklist').then(r => r.json()),
        fetch('/api/acl/whitelist').then(r => r.json()),
        fetch('/api/acl/strikes').then(r => r.json()),
        fetch('/api/rules').then(r => r.json()),
        fetch('/api/logs').then(r => r.json())
      ]);

      if (statsRes.success) setStats(statsRes.stats);
      if (alertsRes.success) setAlerts(alertsRes.alerts);
      if (tenantsRes.success) setTenants(tenantsRes.tenants);
      if (blackRes.success) setBlacklist(blackRes.blacklist);
      if (whiteRes.success) setWhitelist(whiteRes.whitelist);
      if (strikesRes.success) setStrikes(strikesRes.strikes);
      if (rulesRes.success) setRules(rulesRes.rules);
      if (logsRes.success) setLogs(logsRes.logs);
    } catch (err) {
      console.error('Failed to fetch initial SOC data:', err);
    }
  };

  useEffect(() => {
    refreshData();

    // Socket.io Real-time connection
    const socket: Socket = io({
      transports: ['websocket', 'polling']
    });

    socket.on('connect', () => {
      setIsConnected(true);
    });

    socket.on('disconnect', () => {
      setIsConnected(false);
    });

    // Real-time attack interception
    socket.on('attack:detected', (alert: SecurityAlert) => {
      setAlerts(prev => [alert, ...prev]);

      // Update local quick stats
      setStats(prev => {
        if (!prev) return null;
        return {
          ...prev,
          totalRequests: prev.totalRequests + 1,
          totalBlocked: prev.totalBlocked + 1,
          categoryDistribution: {
            ...prev.categoryDistribution,
            [alert.category]: (prev.categoryDistribution[alert.category] || 0) + 1
          }
        };
      });
    });

    // Real-time access log stream (passed, blocked, rate-limited)
    socket.on('access:log', (logItem: AccessLog) => {
      setLogs(prev => [logItem, ...prev.slice(0, 99)]);
    });

    // Real-time Strike Count Update
    socket.on('strike:updated', () => {
      fetch('/api/acl/strikes')
        .then(r => r.json())
        .then(data => {
          if (data.success) setStrikes(data.strikes);
        })
        .catch(() => {});
    });

    // Real-time IP Auto-Ban by 3x Strike Shield
    socket.on('ip:banned', (banned: BlacklistedIp) => {
      setBlacklist(prev => {
        if (prev.find(b => b.ip === banned.ip)) return prev;
        return [banned, ...prev];
      });
      setStats(prev => (prev ? { ...prev, bannedIpCount: prev.bannedIpCount + 1 } : null));
    });

    // Periodic stats sync
    socket.on('stats:updated', (newStats: OverviewStats) => {
      setStats(newStats);
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  // Action Handlers
  const handleBanIp = async (ip: string, reason: string) => {
    try {
      const res = await fetch('/api/acl/blacklist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason })
      });
      const data = await res.json();
      if (data.success) {
        setBlacklist(data.blacklist);
        setStats(prev => (prev ? { ...prev, bannedIpCount: data.blacklist.length } : null));
      }
    } catch (err) {
      console.error('Failed to ban IP:', err);
    }
  };

  const handleUnbanIp = async (ip: string) => {
    try {
      const res = await fetch(`/api/acl/blacklist/${encodeURIComponent(ip)}`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (data.success) {
        setBlacklist(data.blacklist);
        setStats(prev => (prev ? { ...prev, bannedIpCount: data.blacklist.length } : null));
      }
    } catch (err) {
      console.error('Failed to unban IP:', err);
    }
  };

  const handleAddToWhitelist = async (ip: string, description: string) => {
    try {
      const res = await fetch('/api/acl/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, description })
      });
      const data = await res.json();
      if (data.success) {
        setWhitelist(data.whitelist);
      }
    } catch (err) {
      console.error('Failed to add to whitelist:', err);
    }
  };

  const handleRemoveFromWhitelist = async (ip: string) => {
    try {
      const res = await fetch(`/api/acl/whitelist/${encodeURIComponent(ip)}`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (data.success) {
        setWhitelist(data.whitelist);
      }
    } catch (err) {
      console.error('Failed to remove from whitelist:', err);
    }
  };

  const handleToggleRule = async (id: string, enabled: boolean) => {
    try {
      const res = await fetch(`/api/rules/${id}/toggle`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      });
      const data = await res.json();
      if (data.success) {
        setRules(prev => prev.map(r => (r.id === id ? { ...r, enabled } : r)));
      }
    } catch (err) {
      console.error('Failed to toggle rule:', err);
    }
  };

  const handleAddRule = async (ruleData: Omit<WafRule, 'id'>) => {
    try {
      const res = await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ruleData)
      });
      const data = await res.json();
      if (data.success) {
        setRules(prev => [...prev, data.rule]);
      }
    } catch (err) {
      console.error('Failed to add rule:', err);
    }
  };

  const handleDeleteRule = async (id: string) => {
    try {
      const res = await fetch(`/api/rules/${id}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        setRules(prev => prev.filter(r => r.id !== id));
      }
    } catch (err) {
      console.error('Failed to delete rule:', err);
    }
  };

  const handleAutoProvision = async (newTenant: {
    name: string;
    domain: string;
    upstream: string;
    mode?: 'BLOCKING' | 'DETECTION_ONLY';
    rateLimitPerMin?: number;
  }) => {
    try {
      const res = await fetch('/api/tenants', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newTenant)
      });
      const data = await res.json();
      if (data.success) {
        setTenants(prev => [...prev, data.tenant]);
        setStats(prev => (prev ? { ...prev, tenantCount: prev.tenantCount + 1 } : null));
      }
    } catch (err) {
      console.error('Failed to auto-provision tenant:', err);
    }
  };

  const handleUpdateTenant = async (id: string, updates: Partial<Tenant>) => {
    try {
      const res = await fetch(`/api/tenants/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates)
      });
      const data = await res.json();
      if (data.success) {
        setTenants(prev => prev.map(t => (t.id === id ? data.tenant : t)));
      }
    } catch (err) {
      console.error('Failed to update tenant:', err);
    }
  };

  const handleDeleteTenant = async (id: string) => {
    try {
      const res = await fetch(`/api/tenants/${id}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.success) {
        setTenants(prev => prev.filter(t => t.id !== id));
      }
    } catch (err) {
      console.error('Failed to delete tenant:', err);
    }
  };

  const handleAnalyzeAi = (alert: SecurityAlert) => {
    setCopilotAlert(alert);
    setActiveTab('copilot');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans flex flex-col selection:bg-cyan-500 selection:text-slate-950">
      {/* Top Universal Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isConnected={isConnected}
        bannedCount={blacklist.length}
        strikeCount={stats?.activeStrikesCount || 0}
      />

      {/* Main Container */}
      <div className="flex-1 max-w-7xl w-full mx-auto flex flex-col lg:flex-row">
        {/* Navigation Sidebar */}
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          alertCount={alerts.length}
          strikeCount={stats?.activeStrikesCount || 0}
        />

        {/* Tab Content Canvas */}
        <main className="flex-1 p-4 lg:p-6 overflow-x-hidden">
          {activeTab === 'overview' && (
            <LiveOverview
              stats={stats}
              recentAlerts={alerts}
              setActiveTab={setActiveTab}
              onSelectAlert={setSelectedAlert}
            />
          )}

          {activeTab === 'alerts' && (
            <SecurityAlerts
              alerts={alerts}
              onSelectAlert={setSelectedAlert}
              onAnalyzeAi={handleAnalyzeAi}
              onBanIp={handleBanIp}
            />
          )}

          {activeTab === 'threats' && (
            <ThreatActors
              blacklist={blacklist}
              whitelist={whitelist}
              strikes={strikes}
              onBanIp={handleBanIp}
              onUnbanIp={handleUnbanIp}
              onAddToWhitelist={handleAddToWhitelist}
              onRemoveFromWhitelist={handleRemoveFromWhitelist}
            />
          )}

          {activeTab === 'tenants' && (
            <EndpointsHealth
              tenants={tenants}
              onAutoProvision={handleAutoProvision}
              onUpdateTenant={handleUpdateTenant}
              onDeleteTenant={handleDeleteTenant}
            />
          )}

          {activeTab === 'logs' && <AccessLogs logs={logs} />}

          {activeTab === 'control' && (
            <ControlPanel
              rules={rules}
              onToggleRule={handleToggleRule}
              onAddRule={handleAddRule}
              onDeleteRule={handleDeleteRule}
            />
          )}

          {activeTab === 'copilot' && (
            <AiAssistant
              initialAlert={copilotAlert}
              onClearInitialAlert={() => setCopilotAlert(null)}
            />
          )}
        </main>
      </div>

      {/* Forensic Incident Detail Drawer/Modal */}
      <AlertDetailModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onAnalyzeAi={handleAnalyzeAi}
        onBanIp={handleBanIp}
        onWhitelistIp={handleAddToWhitelist}
      />
    </div>
  );
}
export default App;
