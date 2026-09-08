import React, { useState } from 'react';
import {
  Bot,
  Send,
  Sparkles,
  ShieldAlert,
  Terminal,
  RotateCcw,
  CheckCircle2,
  FileText,
  HelpCircle
} from 'lucide-react';
import { SecurityAlert } from '../types.ts';

interface AiAssistantProps {
  initialAlert?: SecurityAlert | null;
  onClearInitialAlert?: () => void;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

const PRESET_PROMPTS = [
  'Analyze recent critical attack trends and recommend rule hardening.',
  'How should our engineering team fix the SQL Injection vulnerability in the backend?',
  'Explain how OAT Security 3x Strike Shield prevents automated brute-force / bots.',
  'Draft an Executive Incident Summary Report for the latest attacks.'
];

export const AiAssistant: React.FC<AiAssistantProps> = ({
  initialAlert,
  onClearInitialAlert
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content:
        'Greetings SOC Analyst. I am your **OAT Security AI Copilot**, powered by server-side Gemini intelligence. I analyze real-time WAF telemetry, reverse-proxy logs, payload signatures, and OWASP Top 10 vectors. How can I assist your investigation today?',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  // If opened with a specific alert
  React.useEffect(() => {
    if (initialAlert) {
      handleAnalyzeIncident(initialAlert);
    }
  }, [initialAlert]);

  const handleAnalyzeIncident = async (alert: SecurityAlert) => {
    setLoading(true);
    const userMsg: Message = {
      role: 'user',
      content: `Analyze Incident ${alert.id}: ${alert.category} attack (${alert.ruleName}) from ${alert.clientIp} against ${alert.tenantDomain}. Matched snippet: "${alert.matchedSnippet}"`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };
    setMessages(prev => [...prev, userMsg]);

    try {
      const res = await fetch('/api/copilot/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert })
      });
      const data = await res.json();
      const botMsg: Message = {
        role: 'assistant',
        content: data.analysis || 'Analysis complete.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages(prev => [...prev, botMsg]);
    } catch (err: any) {
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: `Unable to complete AI analysis: ${err.message}`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setLoading(false);
      if (onClearInitialAlert) onClearInitialAlert();
    }
  };

  const handleSendMessage = async (customText?: string) => {
    const textToSend = customText || input;
    if (!textToSend.trim() || loading) return;

    const userMsg: Message = {
      role: 'user',
      content: textToSend.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await fetch('/api/copilot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: textToSend.trim(),
          history: messages.map(m => ({ role: m.role, content: m.content }))
        })
      });
      const data = await res.json();
      const botMsg: Message = {
        role: 'assistant',
        content: data.response || 'No response generated.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages(prev => [...prev, botMsg]);
    } catch (err: any) {
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: `AI Copilot service error: ${err.message}`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              Gemini AI SOC Copilot &amp; Incident Investigator
              <span className="px-2 py-0.5 rounded text-[10px] bg-purple-950 border border-purple-800 text-purple-300 font-bold">
                GenAI 2.5
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Deep forensic root-cause analysis, CVSS scoring, patch generation, and remediation guidance.
            </p>
          </div>
        </div>

        <button
          onClick={() => setMessages([messages[0]])}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors shrink-0"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset Session</span>
        </button>
      </div>

      {/* Preset Action Buttons */}
      <div className="flex flex-wrap gap-2 text-xs">
        {PRESET_PROMPTS.map((prompt, i) => (
          <button
            key={i}
            onClick={() => handleSendMessage(prompt)}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-300 transition-colors flex items-center gap-1.5 text-left disabled:opacity-50"
          >
            <Sparkles className="w-3 h-3 text-purple-400 shrink-0" />
            <span className="truncate max-w-xs">{prompt}</span>
          </button>
        ))}
      </div>

      {/* Chat Messages Box */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 p-4 shadow-sm flex flex-col h-[520px]">
        <div className="flex-1 overflow-y-auto space-y-4 pr-2">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.role === 'assistant' && (
                <div className="w-7 h-7 rounded-lg bg-purple-500/20 border border-purple-500/40 text-purple-300 flex items-center justify-center shrink-0 mt-0.5">
                  <Bot className="w-4 h-4" />
                </div>
              )}
              <div
                className={`max-w-2xl rounded-xl p-3.5 text-xs leading-relaxed space-y-2 ${
                  msg.role === 'user'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'bg-slate-950 border border-slate-800 text-slate-200 shadow-inner'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] opacity-70 mb-1">
                  <span className="font-bold">
                    {msg.role === 'user' ? 'SOC Analyst' : 'AI Security Copilot'}
                  </span>
                  <span>{msg.timestamp}</span>
                </div>
                <div className="whitespace-pre-wrap font-sans break-words">
                  {msg.content}
                </div>
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex gap-3 justify-start">
              <div className="w-7 h-7 rounded-lg bg-purple-500/20 border border-purple-500/40 text-purple-300 flex items-center justify-center shrink-0">
                <Bot className="w-4 h-4 animate-spin" />
              </div>
              <div className="rounded-xl p-3 bg-slate-950 border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-purple-400 animate-ping" />
                <span>Consulting Gemini Threat Intelligence...</span>
              </div>
            </div>
          )}
        </div>

        {/* Input Bar */}
        <div className="pt-3 border-t border-slate-800 mt-2">
          <form
            onSubmit={e => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              placeholder="Ask AI Copilot regarding threats, payloads, rule tuning, or CVE mitigations..."
              value={input}
              onChange={e => setInput(e.target.value)}
              disabled={loading}
              className="flex-1 px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 text-xs"
            />
            <button
              type="submit"
              disabled={loading || !input.trim()}
              className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs transition-colors flex items-center gap-1.5 disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
