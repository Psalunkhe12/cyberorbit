import express from 'express';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
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

// Router to support both /api/... and direct rewritten paths
const router = express.Router();

router.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'CyberOrbit SOC Command', timestamp: new Date().toISOString() });
});

// Orbit AI Copilot Chat Endpoint
router.post('/copilot', async (req, res) => {
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
router.post('/simulate-attack', async (req, res) => {
  try {
    if (!ai) {
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
router.post('/analyze-packet', async (req, res) => {
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

// Attach router to both /api and / to handle any rewrite scenario
app.use('/api', router);
app.use('/', router);

export default app;
