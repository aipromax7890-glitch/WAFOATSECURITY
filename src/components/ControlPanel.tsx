import React, { useState } from 'react';
import {
  Sliders,
  Plus,
  Trash2,
  Check,
  X,
  Code,
  Shield,
  HelpCircle,
  FileCode2
} from 'lucide-react';
import { WafRule } from '../types.ts';

interface ControlPanelProps {
  rules: WafRule[];
  onToggleRule: (id: string, enabled: boolean) => Promise<void>;
  onAddRule: (rule: Omit<WafRule, 'id'>) => Promise<void>;
  onDeleteRule: (id: string) => Promise<void>;
}

export const ControlPanel: React.FC<ControlPanelProps> = ({
  rules,
  onToggleRule,
  onAddRule,
  onDeleteRule
}) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [name, setName] = useState('');
  const [category, setCategory] = useState<'SQLi' | 'XSS' | 'LFI' | 'RCE' | 'CSRF' | 'Malware' | 'Custom'>('Custom');
  const [severity, setSeverity] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('HIGH');
  const [pattern, setPattern] = useState('');
  const [target, setTarget] = useState<'all' | 'url' | 'query' | 'headers' | 'body'>('all');
  const [description, setDescription] = useState('');

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !pattern) return;
    await onAddRule({
      name,
      category,
      severity,
      pattern,
      target,
      description,
      enabled: true
    });
    setName('');
    setPattern('');
    setDescription('');
    setShowAddModal(false);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            WAF Universal Inspection Rules &amp; Policy
          </h2>
          <p className="text-xs text-slate-400">
            Fine-tune active signature detection engines. Rules take effect immediately across all proxied tenants.
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-all shrink-0"
        >
          <Plus className="w-4 h-4" />
          <span>Add Custom Rule</span>
        </button>
      </div>

      {/* Rules Table */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase text-[10px] tracking-wider">
                <th className="py-2.5 px-3.5">Status</th>
                <th className="py-2.5 px-3">Rule ID &amp; Name</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Target Layer</th>
                <th className="py-2.5 px-3">Regex Pattern</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {rules.map(rule => (
                <tr key={rule.id} className="hover:bg-slate-850/50 transition-colors">
                  {/* Status Toggle Switch */}
                  <td className="py-2.5 px-3.5 whitespace-nowrap">
                    <button
                      onClick={() => onToggleRule(rule.id, !rule.enabled)}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                        rule.enabled ? 'bg-cyan-500' : 'bg-slate-700'
                      }`}
                      title={rule.enabled ? 'Disable Rule' : 'Enable Rule'}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                          rule.enabled ? 'translate-x-4.5' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </td>

                  {/* ID & Name */}
                  <td className="py-2.5 px-3">
                    <div className="font-semibold text-slate-200">{rule.name}</div>
                    <div className="text-[10px] font-mono text-slate-500">{rule.id}</div>
                  </td>

                  {/* Category */}
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        rule.category === 'SQLi'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : rule.category === 'XSS'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : rule.category === 'RCE'
                          ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                          : rule.category === 'LFI'
                          ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                          : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                      }`}
                    >
                      {rule.category}
                    </span>
                  </td>

                  {/* Severity */}
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                        rule.severity === 'CRITICAL'
                          ? 'bg-red-950 text-red-300 border border-red-800'
                          : rule.severity === 'HIGH'
                          ? 'bg-orange-950 text-orange-300 border border-orange-800'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {rule.severity}
                    </span>
                  </td>

                  {/* Target Layer */}
                  <td className="py-2.5 px-3 whitespace-nowrap text-slate-300 font-mono text-[11px] uppercase">
                    {rule.target || 'ALL'}
                  </td>

                  {/* Regex Pattern */}
                  <td className="py-2.5 px-3 font-mono text-[11px] text-cyan-300 max-w-[280px] truncate" title={rule.pattern}>
                    <code className="bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                      {rule.pattern}
                    </code>
                  </td>

                  {/* Action */}
                  <td className="py-2.5 px-3 text-right whitespace-nowrap">
                    {rule.id.startsWith('RULE-CUST-') && (
                      <button
                        onClick={() => onDeleteRule(rule.id)}
                        className="p-1 rounded hover:bg-red-950 text-slate-500 hover:text-red-400 transition-colors"
                        title="Delete custom rule"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deployment & Testing Quick Reference */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
          <FileCode2 className="w-4 h-4 text-cyan-400" />
          Gateway DNS &amp; Proxy Configuration Guide
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          To protect a real web application (DVWA, WordPress, Node.js, PHP, or Java backend), configure DNS A Record or CNAME to point to this OAT Security WAF Gateway. The gateway inspects incoming traffic on Port 3000 and transparently proxies legitimate requests to the registered Upstream Target.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] space-y-1.5 text-slate-300">
            <div className="text-cyan-400 font-bold">Client curl with Host header:</div>
            <div className="text-slate-400">
              curl -i -H "Host: dvwa.internal.oatsec.io" \<br />
              &nbsp;&nbsp;http://localhost:3000/vulnerabilities/sqli/?id=1
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] space-y-1.5 text-slate-300">
            <div className="text-rose-400 font-bold">Live Attack Test via Terminal (Direct 403 Block):</div>
            <div className="text-slate-400">
              curl -i -H "Host: dvwa.internal.oatsec.io" \<br />
              &nbsp;&nbsp;"http://localhost:3000/?id=1'%20OR%20'1'='1"
            </div>
          </div>
        </div>
      </div>

      {/* Add Custom Rule Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Plus className="w-4 h-4 text-cyan-400" />
                Add Custom WAF Regex Rule
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-500 hover:text-white text-xs font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Rule Name</label>
                <input
                  type="text"
                  placeholder="e.g. Block Spring4Shell CVE-2022-22965"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Category</label>
                  <select
                    value={category}
                    onChange={e => setCategory(e.target.value as any)}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                  >
                    <option value="SQLi">SQL Injection</option>
                    <option value="XSS">XSS</option>
                    <option value="LFI">Path Traversal / LFI</option>
                    <option value="RCE">Remote Code Execution</option>
                    <option value="Malware">Malware / Web Shell</option>
                    <option value="CSRF">CSRF</option>
                    <option value="Custom">Custom Vector</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Severity</label>
                  <select
                    value={severity}
                    onChange={e => setSeverity(e.target.value as any)}
                    className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                  >
                    <option value="CRITICAL">CRITICAL (Strikes + Auto-Ban)</option>
                    <option value="HIGH">HIGH (Strikes + Auto-Ban)</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Inspection Target</label>
                <select
                  value={target}
                  onChange={e => setTarget(e.target.value as any)}
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                >
                  <option value="all">All Layers (URL, Query, Headers, Body)</option>
                  <option value="url">URL Path Only</option>
                  <option value="query">Query Parameters (GET)</option>
                  <option value="headers">HTTP Headers (User-Agent, Cookie)</option>
                  <option value="body">Request Body (POST/JSON/Form)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Regex Pattern (e.g. <code>(?i)class\.module\.classLoader</code>)
                </label>
                <input
                  type="text"
                  placeholder="Regex pattern string..."
                  value={pattern}
                  onChange={e => setPattern(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Description</label>
                <input
                  type="text"
                  placeholder="Explanation of what this rule catches..."
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
                >
                  Save Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
