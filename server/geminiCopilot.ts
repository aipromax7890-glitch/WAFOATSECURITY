import { GoogleGenAI } from '@google/genai';

let aiClient: GoogleGenAI | null = null;

function getAiClient(): GoogleGenAI | null {
  if (!process.env.GEMINI_API_KEY) {
    return null;
  }
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

export interface IncidentAnalysisRequest {
  incidentId: string;
  category: string;
  ruleName: string;
  severity: string;
  payload: string;
  url: string;
  method: string;
  clientIp: string;
  targetDomain: string;
  customPrompt?: string;
}

export async function analyzeSecurityIncident(data: IncidentAnalysisRequest): Promise<{
  analysis: string;
  threatLevel: string;
  cweMapping: string;
  remediationSteps: string[];
}> {
  const client = getAiClient();

  const fallbackResponse = {
    analysis: `[Offline Heuristic Engine] Detected ${data.category} threat payload (${data.ruleName}). The request targeted ${data.method} ${data.url} with malicious payload snippet: "${data.payload}". This pattern attempts to exploit unvalidated inputs to bypass application safeguards or execute unauthorized operations.`,
    threatLevel: data.severity,
    cweMapping: data.category === 'SQLi' ? 'CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)' :
                data.category === 'XSS' ? 'CWE-79 (Improper Neutralization of Input During Web Page Generation)' :
                data.category === 'LFI' ? 'CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)' :
                data.category === 'RCE' ? 'CWE-78 (Improper Neutralization of Special Elements used in an OS Command)' :
                data.category === 'Malware' ? 'CWE-434 (Unrestricted Upload of File with Dangerous Type)' :
                'CWE-352 (Cross-Site Request Forgery)',
    remediationSteps: [
      data.category === 'SQLi' ? 'Implement Prepared Statements (Parameterized Queries) with PDO / ORM; forbid dynamic string concatenation.' :
      data.category === 'XSS' ? 'Context-aware HTML entity encoding and enforce a strict Content-Security-Policy (CSP) HTTP header.' :
      data.category === 'LFI' ? 'Sanitize filenames using path.basename(), validate against a strict whitelist, and disable PHP file stream wrappers.' :
      'Enforce strict input validation, least-privilege execution credentials, and maintain real-time WAF rule updates.'
    ]
  };

  if (!client) {
    return fallbackResponse;
  }

  try {
    const prompt = `You are a Senior Principal SOC Security Analyst & Cloud Application Firewall Architect at OAT Security.
Analyze this security incident detected by the WAF:
- Incident ID: ${data.incidentId}
- Attack Vector: ${data.category} (${data.ruleName})
- Severity: ${data.severity}
- Source IP: ${data.clientIp}
- Target Domain: ${data.targetDomain}
- Target URL: ${data.method} ${data.url}
- Detected Malicious Payload: ${data.payload}
${data.customPrompt ? `Additional Analyst Query: ${data.customPrompt}` : ''}

Provide an authoritative, actionable SOC security brief formatted in clear sections:
1. Executive Summary & Attacker Intent
2. Technical Payload Breakdown (deconstruct what the payload was trying to do)
3. OWASP & CWE Classification
4. Actionable Backend Code Remediation & Defensive Hardening
5. WAF & Firewall Policy Recommendation

Respond in professional English or Indonesian as appropriate, concise and rich in cybersecurity precision.`;

    let text = '';
    const candidateModels = ['gemini-3.5-flash-lite', 'gemini-3.6-flash'];
    for (const modelName of candidateModels) {
      try {
        const response = await client.models.generateContent({
          model: modelName,
          contents: prompt,
          config: {
            systemInstruction: 'You are OAT Security AI Copilot, an elite cybersecurity incident responder and cloud WAF engineer.',
            temperature: 0.3
          }
        });
        if (response.text) {
          text = response.text;
          break;
        }
      } catch (e) {
        console.warn(`[Copilot] Incident analysis failed with ${modelName}:`, e);
      }
    }

    text = text || fallbackResponse.analysis;

    return {
      analysis: text,
      threatLevel: data.severity,
      cweMapping: fallbackResponse.cweMapping,
      remediationSteps: fallbackResponse.remediationSteps
    };
  } catch (err) {
    console.error('Gemini API Incident Analysis error:', err);
    return fallbackResponse;
  }
}

export async function chatWithCopilot(
  query: string,
  history: Array<{ role: string; content: string }> = []
): Promise<string> {
  const client = getAiClient();
  if (!client) {
    return `[AI Copilot Advisory] Regarding "${query}":\n\n1. **Attack Vector Evaluation**: Review detected payloads in URL query, POST body, and HTTP headers.\n2. **3x Strike Shield Enforcement**: Malicious IPs reaching 3 critical/high strikes are permanently banned in real-time.\n3. **Defense in Depth**: Pair WAF regex signature inspection with backend input sanitization, parameterized SQL queries, and strict CSP headers.`;
  }

  try {
    const formattedHistory = history.map(h => `${h.role === 'user' ? 'Analyst' : 'Copilot'}: ${h.content}`).join('\n\n');
    const prompt = `You are OAT Security AI Copilot, a senior SOC analyst and WAF security engineer.
Recent conversation history:
${formattedHistory}

Current analyst query:
${query}

Provide a comprehensive, highly technical, and practical cybersecurity response. Focus on WAF rules, OWASP Top 10 defenses, reverse proxy tuning, and incident containment.`;

    const candidateModels = ['gemini-3.5-flash-lite', 'gemini-3.6-flash'];
    for (const modelName of candidateModels) {
      try {
        const response = await client.models.generateContent({
          model: modelName,
          contents: prompt,
          config: {
            systemInstruction: 'You are OAT Security AI Copilot, a world-class Web Application Firewall and SOC intelligence assistant.',
            temperature: 0.4
          }
        });
        if (response.text) {
          return response.text;
        }
      } catch (e) {
        console.warn(`[Copilot] Chat generation failed with ${modelName}:`, e);
      }
    }

    return `AI Copilot Advisory regarding "${query}": Ensure all input parameters are strictly validated and parameterized queries are used to defend against SQLi. WAF 3x Strike Shield automatically quarantines repeat offenders.`;
  } catch (err: any) {
    console.error('Gemini Chat error:', err);
    return `AI Copilot Advisory regarding "${query}": Ensure all input parameters are strictly validated and parameterized queries are used to defend against SQLi. WAF 3x Strike Shield automatically quarantines repeat offenders.`;
  }
}

