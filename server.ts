import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Initialize Gemini AI client
  const apiKey = process.env.GEMINI_API_KEY;
  let ai: GoogleGenAI | null = null;
  if (apiKey) {
    ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }

  // --- API Routes ---

  // Orbit AI Copilot Chat Endpoint
  app.post('/api/copilot', async (req, res) => {
    try {
      const { message, context, history } = req.body;

      if (!ai) {
        return res.json({
          reply: `[Demo Mode - No API Key Set] Processed inquiry: "${message}". All edge proxies report normal operations. Recommendation: Monitor SYN threshold on gateway-01.`,
        });
      }

      const systemInstruction = `You are Orbit AI, an expert Senior SOC (Security Operations Center) Security Copilot embedded in CyberOrbit Command Center.
Your duty is to provide clear, actionable, precise security intelligence, threat analysis, incident response steps, and firewall rule recommendations.
Be professional, concise, authoritative yet helpful. Use technical security terminology (CVEs, TCP flags, WAF, BGP Flowspec, Rate Limiting, GeoIP isolation) naturally.
Context about current dashboard state: ${JSON.stringify(context || {})}`;

      const contents = [
        ...(history || []).map((h: { sender: string; text: string }) => ({
          role: h.sender === 'user' ? 'user' : 'model',
          parts: [{ text: h.text }],
        })),
        {
          role: 'user',
          parts: [{ text: message }],
        },
      ];

      const response = await ai.models.generateContent({
        model: 'gemini-3.6-flash',
        contents,
        config: {
          systemInstruction,
          temperature: 0.7,
        },
      });

      const reply = response.text || 'No response generated from Orbit AI.';
      res.json({ reply });
    } catch (err: any) {
      console.error('Error in /api/copilot:', err);
      res.status(500).json({
        error: err.message || 'Failed to query Orbit AI Copilot.',
        reply: 'Apologies, an anomaly occurred while correlating telemetry logs with Orbit AI. Proceeding with local heuristics.',
      });
    }
  });

  // Synthetic Attack Generator Endpoint
  app.post('/api/simulate-attack', async (req, res) => {
    try {
      if (!ai) {
        // Fallback simulation
        return res.json({
          scenarioName: 'DDoS SYN Flood Spike',
          vector: { origin: 'FRA / DE', target: 'BOM / IN', riskScore: 84 },
          anomaly: {
            severity: 'CRITICAL',
            event: 'Layer 7 HTTP/2 Flood & SYN Spike',
            ip: `${Math.floor(Math.random() * 200 + 10)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254 + 1)}`,
            asset: 'auth-gateway-01',
            payloadSnippet: 'POST /v1/auth/login HTTP/2.0 Header: X-Forwarded-For random-spoof',
            confidence: 94,
            mitigationRule: 'Rate-limit 100 req/min per ASN + IP Challenge',
          },
        });
      }

      const prompt = `Generate a realistic synthetic cybersecurity attack scenario for a SOC Command dashboard simulation.
Return a JSON object with:
1. scenarioName (string, e.g. "Credential Stuffing Campaign on Auth Cluster")
2. vector: { origin: "CITY / CC", target: "CITY / CC", riskScore: number (50-98) }
3. anomaly: {
     severity: "CRITICAL" | "HIGH" | "MEDIUM",
     event: string,
     ip: string (IPv4),
     asset: string,
     payloadSnippet: string,
     confidence: number (80-99),
     mitigationRule: string
   }`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.6-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.9,
        },
      });

      const text = response.text || '{}';
      const data = JSON.parse(text);
      res.json(data);
    } catch (err: any) {
      console.error('Error in /api/simulate-attack:', err);
      res.json({
        scenarioName: 'UDP Amplification Attack',
        vector: { origin: 'SGP / SG', target: 'IHN / US', riskScore: 78 },
        anomaly: {
          severity: 'HIGH',
          event: 'NTP Reflection Volumetric Spike',
          ip: '198.51.100.42',
          asset: 'dns-resolver-04',
          payloadSnippet: 'UDP / 123 MONLIST packet surge',
          confidence: 88,
          mitigationRule: 'Drop NTP monlist requests at edge router',
        },
      });
    }
  });

  // Deep Anomaly Payload Analyzer Endpoint
  app.post('/api/analyze-packet', async (req, res) => {
    try {
      const { anomaly } = req.body;
      if (!ai) {
        return res.json({
          analysis: `Analysis for ${anomaly?.event || 'Event'}: Suspected botnet probe originating from ${anomaly?.ip || 'IP'}. Request payload matches automated vulnerability scanning signatures.`,
          recommendedActions: [
            'Apply automatic IP ban to firewall ACL',
            'Enforce Cloudflare Turnstile CAPTCHA on endpoint',
            'Update signature rule in WAF Engine',
          ],
        });
      }

      const prompt = `Perform a SOC Incident Triage Analysis for this detected threat anomaly:
${JSON.stringify(anomaly, null, 2)}

Provide a structured analysis including:
1. Threat summary & intent
2. Risk assessment & potential business impact
3. 3-4 clear step-by-step containment & mitigation instructions.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.6-flash',
        contents: prompt,
      });

      res.json({
        analysis: response.text,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Structured Alert AI Security Analysis Endpoint
  app.post('/api/analyze-alert', async (req, res) => {
    try {
      const { alert } = req.body;
      if (!alert) {
        return res.status(400).json({ error: 'Alert payload required.' });
      }

      if (!ai) {
        // Structured fallback when Gemini API key is missing
        return res.json({
          summary: `High severity security event (${alert.event || 'Anomaly'}) detected from source ${alert.ip || 'Unknown IP'} targeting ${alert.asset || 'Internal Asset'}.`,
          possible_attack_type: alert.attackVector || alert.event || 'Network Telemetry Anomaly',
          evidence_explanation: `Detected suspicious payload "${alert.payloadSnippet || 'Abnormal traffic spike'}" with ${alert.confidence || 90}% detection confidence score.`,
          recommended_investigation_steps: [
            `Verify active network socket connections on ${alert.asset || 'target asset'}.`,
            `Inspect authentication and application logs around timestamp ${alert.timestamp || 'event time'}.`,
            `Cross-reference source IP ${alert.ip || 'origin'} against threat intelligence feeds.`,
            `Audit ingress firewall and WAF ACL rules.`
          ],
          recommended_containment_options: [
            `Apply rate-limiting or ACL drop rule to source IP ${alert.ip || 'origin'}.`,
            `Quarantine target asset ${alert.asset || 'host'} if lateral movement is observed.`,
            `Deploy WAF signature update to block payload pattern.`
          ],
          confidence: 0.88,
          is_advisory_only: true
        });
      }

      const prompt = `You are Gemini SOC Copilot. Perform a structured AI Security Analysis for this alert:
${JSON.stringify(alert, null, 2)}

Respond strictly with a JSON object matching this schema:
{
  "summary": "<Concise 1-2 sentence executive overview>",
  "possible_attack_type": "<Specific security attack classification>",
  "evidence_explanation": "<Detailed evidence breakdown of payload and telemetry>",
  "recommended_investigation_steps": ["<Step 1>", "<Step 2>", ...],
  "recommended_containment_options": ["<Option 1>", "<Option 2>", ...],
  "confidence": <Float between 0.0 and 1.0>
}`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.6-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.3,
        },
      });

      const text = response.text || '{}';
      const parsed = JSON.parse(text);
      res.json(parsed);
    } catch (err: any) {
      console.error('Error in /api/analyze-alert:', err);
      res.status(500).json({ error: err.message || 'Failed to generate AI Security Analysis.' });
    }
  });

  // --- Human-in-the-Loop Response Actions Endpoints ---
  let memoryResponseActions = [
    {
      id: 'act-101',
      requested_by: 'Gemini SOC Copilot',
      approved_by: 'Pending Analyst Review',
      action: 'block_ip',
      target: '198.51.100.99',
      reason: 'Volumetric HTTP/2 flood & SYN surge detected from source IP.',
      timestamp: new Date().toISOString(),
      status: 'PENDING',
      command_executed: null,
    },
    {
      id: 'act-102',
      requested_by: 'Gemini SOC Copilot',
      approved_by: 'Pending Analyst Review',
      action: 'isolate_host',
      target: 'auth-gateway-01',
      reason: 'Potential credential stuffing surge & multi-stage brute force.',
      timestamp: new Date().toISOString(),
      status: 'PENDING',
      command_executed: null,
    },
    {
      id: 'act-103',
      requested_by: 'Gemini SOC Copilot',
      approved_by: 'Sarah Chen (SOC Lead)',
      action: 'investigate_host',
      target: 'db-cluster-primary',
      reason: 'Automated vulnerability scanning payload detected.',
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      status: 'APPROVED',
      command_executed: 'soc-collector capture-dump --host=db-cluster-primary',
    },
  ];

  // Memory Audit Logs Store
  const VALID_AUDIT_ACTIONS = [
    'LOGIN',
    'ALERT_ACKNOWLEDGED',
    'INCIDENT_CREATED',
    'INCIDENT_UPDATED',
    'INCIDENT_RESOLVED',
    'RULE_CREATED',
    'RULE_UPDATED',
    'AI_ANALYSIS_GENERATED',
    'RESPONSE_REQUESTED',
    'RESPONSE_APPROVED',
    'RESPONSE_REJECTED',
  ];

  let memoryAuditLogs: any[] = [
    {
      id: 'audit-101',
      user: 'admin@cyberorbit.sec',
      action: 'LOGIN',
      entity: 'session-admin-01',
      old_value: null,
      new_value: { status: 'AUTHENTICATED', role: 'ADMIN' },
      timestamp: new Date(Date.now() - 7200000).toISOString(),
    },
    {
      id: 'audit-102',
      user: 'sarah.chen@cyberorbit.sec',
      action: 'RESPONSE_APPROVED',
      entity: 'act-103',
      old_value: { status: 'PENDING' },
      new_value: { status: 'APPROVED', action: 'MONITOR_HOST', target: 'db-cluster-primary' },
      timestamp: new Date(Date.now() - 3600000).toISOString(),
    },
  ];

  app.get('/api/audit-logs', (req, res) => {
    res.json(memoryAuditLogs);
  });

  app.post('/api/audit-logs', (req, res) => {
    const { user, action, entity, old_value = null, new_value = null, timestamp } = req.body;
    const actionClean = String(action || '').toUpperCase().trim();

    if (!VALID_AUDIT_ACTIONS.includes(actionClean)) {
      return res.status(400).json({
        error: `Invalid audit action '${action}'. Must be one of: ${VALID_AUDIT_ACTIONS.join(', ')}`,
      });
    }

    const newRecord = {
      id: `audit-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      user: user || 'SYSTEM',
      action: actionClean,
      entity: entity || 'N/A',
      old_value,
      new_value,
      timestamp: timestamp || new Date().toISOString(),
    };

    memoryAuditLogs.unshift(newRecord);
    res.json(newRecord);
  });

  app.get('/api/response-actions', (req, res) => {
    res.json(memoryResponseActions);
  });

  app.post('/api/response-actions/recommend', (req, res) => {
    const { action, target, reason, requested_by } = req.body;
    const newRecord = {
      id: `act-${Date.now()}`,
      requested_by: requested_by || 'Gemini SOC Copilot',
      approved_by: 'Pending Analyst Review',
      action: action || 'monitor_traffic',
      target: target || 'Unknown Target',
      reason: reason || 'AI recommended containment advisory.',
      timestamp: new Date().toISOString(),
      status: 'PENDING', // AI CANNOT DIRECTLY EXECUTE - ALWAYS PENDING
      command_executed: null,
    };

    memoryResponseActions.unshift(newRecord);

    // Audit log
    const auditRecord = {
      id: `audit-${Date.now()}`,
      user: newRecord.requested_by,
      action: 'RESPONSE_REQUESTED',
      entity: newRecord.id,
      old_value: null,
      new_value: { action: newRecord.action, target: newRecord.target, reason: newRecord.reason, status: 'PENDING' },
      timestamp: newRecord.timestamp,
    };
    memoryAuditLogs.unshift(auditRecord);

    res.json(newRecord);
  });

  app.post('/api/response-actions/decide', (req, res) => {
    const { action_id, decision, approved_by } = req.body;
    const record = memoryResponseActions.find((a) => a.id === action_id);

    if (!record) {
      return res.status(404).json({ error: 'Response action record not found.' });
    }

    if (decision !== 'APPROVED' && decision !== 'REJECTED') {
      return res.status(400).json({ error: 'Decision must be APPROVED or REJECTED.' });
    }

    const oldStatus = record.status;
    record.approved_by = approved_by || 'Sarah Chen (SOC Lead)';
    record.status = decision;
    record.timestamp = new Date().toISOString();

    if (decision === 'APPROVED') {
      const act = String(record.action).toUpperCase();
      let cmd = `[SIMULATED] iptables -A INPUT -s ${record.target} -j DROP`;
      if (act === 'UNBLOCK_IP') cmd = `[SIMULATED] iptables -D INPUT -s ${record.target} -j DROP`;
      else if (act === 'ISOLATE_HOST') cmd = `[SIMULATED] network-cli host isolate --target=${record.target}`;
      else if (act === 'MONITOR_HOST') cmd = `[SIMULATED] tcpdump -i any host ${record.target} -w /var/log/cyberorbit/monitor-${record.target}.pcap`;

      record.status = 'SIMULATED';
      record.command_executed = cmd;

      memoryAuditLogs.unshift({
        id: `audit-${Date.now()}`,
        user: record.approved_by,
        action: 'RESPONSE_APPROVED',
        entity: record.id,
        old_value: { status: oldStatus },
        new_value: { status: 'APPROVED', action: record.action, target: record.target, command_executed: cmd },
        timestamp: record.timestamp,
      });
    } else {
      memoryAuditLogs.unshift({
        id: `audit-${Date.now()}`,
        user: record.approved_by,
        action: 'RESPONSE_REJECTED',
        entity: record.id,
        old_value: { status: oldStatus },
        new_value: { status: 'REJECTED', action: record.action, target: record.target },
        timestamp: record.timestamp,
      });
    }

    res.json(record);
  });

  // Execute Direct Simulated Response Action Endpoint (BLOCK_IP, UNBLOCK_IP, ISOLATE_HOST, MONITOR_HOST)
  app.post('/api/response-actions/execute-simulated', (req, res) => {
    const { action, target, reason, requested_by, approved_by, incident_id } = req.body;
    const actionUpper = String(action || 'BLOCK_IP').toUpperCase();

    let cmd = `[SIMULATED] iptables -A INPUT -s ${target} -j DROP`;
    let details = `Simulated blocking of IP ${target} via edge firewall.`;
    let incStatus = 'CONTAINED';

    if (actionUpper === 'UNBLOCK_IP') {
      cmd = `[SIMULATED] iptables -D INPUT -s ${target} -j DROP`;
      details = `Simulated unblocking of IP ${target} from edge firewall rules.`;
      incStatus = 'ACKNOWLEDGED';
    } else if (actionUpper === 'ISOLATE_HOST') {
      cmd = `[SIMULATED] network-cli host isolate --target=${target} --policy=quarantine-vlan`;
      details = `Simulated quarantining host ${target} into isolated VLAN segment.`;
      incStatus = 'CONTAINED';
    } else if (actionUpper === 'MONITOR_HOST') {
      cmd = `[SIMULATED] tcpdump -i any host ${target} -w /var/log/cyberorbit/monitor-${target}.pcap`;
      details = `Simulated deep packet capture stream initiated for host ${target}.`;
      incStatus = 'INVESTIGATING';
    }

    const timestamp = new Date().toISOString();
    const actionRecord = {
      id: `act-${Date.now()}`,
      requested_by: requested_by || 'Gemini SOC Copilot',
      approved_by: approved_by || 'Sarah Chen (SOC Lead)',
      action: actionUpper,
      target: target || 'Unknown Target',
      reason: reason || `Analyst executed ${actionUpper}`,
      timestamp,
      status: 'SIMULATED',
      command_executed: cmd,
      incident_id: incident_id || null,
    };

    memoryResponseActions.unshift(actionRecord);

    const auditEntry = {
      id: `audit-${Date.now()}`,
      user: actionRecord.approved_by,
      action: 'RESPONSE_APPROVED',
      entity: actionRecord.id,
      old_value: { status: 'PENDING' },
      new_value: { status: 'SIMULATED', action: actionUpper, target: target, command_executed: cmd, details },
      timestamp,
    };

    memoryAuditLogs.unshift(auditEntry);

    res.json({
      response_action: actionRecord,
      audit_log: auditEntry,
      incident_update: incident_id ? { incident_id, status: incStatus, updated_at: timestamp } : null,
      simulated_result: {
        action: actionUpper,
        target,
        status: 'SIMULATED',
        command_executed: cmd,
        details,
        timestamp,
      },
    });
  });

  // Vite middleware or production build handling
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
