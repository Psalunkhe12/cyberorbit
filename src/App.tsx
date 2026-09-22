import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { TopHeader } from './components/TopHeader';
import { Toast } from './components/Toast';
import { RoleSwitcherModal } from './components/RoleSwitcherModal';
import {
  NavigationTab,
  Operator,
  AnomalyEvent,
  SecurityRule,
  ThreatVector,
  TrafficPoint,
  ChatMessage,
} from './types';
import {
  INITIAL_TRAFFIC_DATA,
  INITIAL_ANOMALIES,
  INITIAL_RULES,
  INITIAL_THREAT_VECTOR,
  OPERATOR_PROFILES,
} from './data/mockData';

import { OverviewView } from './views/OverviewView';
import { LiveTrafficView } from './views/LiveTrafficView';
import { ThreatIntelView } from './views/ThreatIntelView';
import { AlertsConsoleView } from './views/AlertsConsoleView';
import { RulesEngineView } from './views/RulesEngineView';
import { AttackReplayView } from './views/AttackReplayView';
import { ReportsView } from './views/ReportsView';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavigationTab>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Operator Profile
  const [operator, setOperator] = useState<Operator>(OPERATOR_PROFILES[0]);
  const [isRoleModalOpen, setIsRoleModalOpen] = useState(false);

  // Metrics State
  const [throughput, setThroughput] = useState('1.84');
  const [activeFlows, setActiveFlows] = useState(18429);
  const [threatsCount, setThreatsCount] = useState(7);
  const [mitigatedCount, setMitigatedCount] = useState(24);

  // Simulation & Stream
  const [isSimulating, setIsSimulating] = useState(false);
  const [isLiveTraffic, setIsLiveTraffic] = useState(true);

  // Telemetry Collections
  const [trafficData, setTrafficData] = useState<TrafficPoint[]>(INITIAL_TRAFFIC_DATA);
  const [threatVector, setThreatVector] = useState<ThreatVector>(INITIAL_THREAT_VECTOR);
  const [anomalies, setAnomalies] = useState<AnomalyEvent[]>(INITIAL_ANOMALIES);
  const [rules, setRules] = useState<SecurityRule[]>(INITIAL_RULES);

  // Orbit AI Chat State
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      id: 'msg-0',
      sender: 'bot',
      text: 'Traffic elevated on edge-api-02. Rate limiting applied automatically.',
      timestamp: '15:30',
    },
    {
      id: 'msg-1',
      sender: 'user',
      text: 'What is the priority item?',
      timestamp: '15:31',
    },
    {
      id: 'msg-2',
      sender: 'bot',
      text: 'Review gateway-01 SYN anomaly. 91% confidence score.',
      timestamp: '15:31',
    },
  ]);
  const [isCopilotLoading, setIsCopilotLoading] = useState(false);

  // Toast Helper
  const triggerToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 2500);
  };

  // Tab Handler with Toast
  const handleTabChange = (tab: NavigationTab) => {
    setActiveTab(tab);
    const labels: Record<NavigationTab, string> = {
      overview: 'Overview',
      traffic: 'Live Traffic',
      threats: 'Threat Intel',
      alerts: 'Alerts Console',
      rules: 'Rules Engine',
      replay: 'Attack Replay',
      reports: 'Reports',
    };
    triggerToast(`${labels[tab]} loaded`);
  };

  // Live Traffic Simulation Loop
  useEffect(() => {
    if (!isLiveTraffic) return;
    const interval = setInterval(() => {
      setTrafficData((prev) => {
        const last = prev[prev.length - 1];
        const date = new Date();
        const timeStr = `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
        const delta = (Math.random() * 0.1 - 0.05).toFixed(2);
        const newGbps = Math.max(1.1, parseFloat((parseFloat(last.throughputGbps.toString()) + parseFloat(delta)).toFixed(2)));
        const newFlows = Math.floor(last.activeFlows + (Math.random() * 200 - 100));

        const newPt: TrafficPoint = {
          time: timeStr,
          throughputGbps: newGbps,
          activeFlows: newFlows,
          threatRequests: Math.floor(Math.random() * 300 + 400),
          synPackets: Math.floor(Math.random() * 2000 + 8000),
        };

        setThroughput(newGbps.toString());
        setActiveFlows(newFlows);

        return [...prev.slice(1), newPt];
      });
    }, 3000);

    return () => clearInterval(interval);
  }, [isLiveTraffic]);

  // Run Simulation Handler
  const handleRunSimulation = async () => {
    setIsSimulating(true);
    triggerToast('Synthetic simulation initiated');

    try {
      const res = await fetch('/api/simulate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();

      if (data.anomaly) {
        const date = new Date();
        const timeStr = `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}`;
        
        const newAnom: AnomalyEvent = {
          id: `evt-${Date.now()}`,
          severity: data.anomaly.severity || 'CRITICAL',
          event: data.anomaly.event || 'Synthetic Attack Surge',
          ip: data.anomaly.ip || '198.51.100.99',
          asset: data.anomaly.asset || 'edge-api-02',
          timestamp: timeStr,
          status: 'UNREVIEWED',
          confidence: data.anomaly.confidence || 95,
          payloadSnippet: data.anomaly.payloadSnippet || 'GET /api/v2/products?query=DDoS HTTP/2',
          geoOrigin: data.vector?.origin || 'Frankfurt, DE',
          attackVector: data.scenarioName || 'Layer 7 Flood',
        };

        setAnomalies((prev) => [newAnom, ...prev]);
        setThreatsCount((prev) => prev + 1);

        if (data.vector) {
          setThreatVector((prev) => ({
            ...prev,
            origin: data.vector.origin || prev.origin,
            target: data.vector.target || prev.target,
            riskScore: data.vector.riskScore || 88,
            riskLabel: `Elevated ${data.vector.riskScore || 88}/100`,
            isIsolated: false,
          }));
        }

        // Add Orbit AI Copilot notification
        setChatMessages((prev) => [
          ...prev,
          {
            id: `msg-${Date.now()}`,
            sender: 'bot',
            text: `[SIMULATION] Detected ${data.anomaly.event} from ${data.anomaly.ip}. Recommended mitigation: ${data.anomaly.mitigationRule}`,
            timestamp: timeStr.slice(0, 5),
          },
        ]);
      }
    } catch {
      triggerToast('Simulation data generated locally');
    } finally {
      setIsSimulating(false);
    }
  };

  // Isolate Threat Vector Handler
  const handleIsolateVector = () => {
    const nextIsolated = !threatVector.isIsolated;
    setThreatVector((prev) => ({
      ...prev,
      isIsolated: nextIsolated,
      riskLabel: nextIsolated ? 'Quarantined (8/100)' : 'Elevated 68/100',
    }));

    if (nextIsolated) {
      setMitigatedCount((prev) => prev + 1);
      triggerToast('Target vector isolated');
    } else {
      triggerToast('Target vector re-enabled');
    }
  };

  // Review & Confirm Anomaly
  const handleReviewAnomaly = (id: string) => {
    setAnomalies((prev) =>
      prev.map((a) => {
        if (a.id === id) {
          if (a.status !== 'CONFIRMED' && a.status !== 'MITIGATED') {
            setMitigatedCount((count) => count + 1);
            setThreatsCount((t) => Math.max(0, t - 1));
          }
          return { ...a, status: 'CONFIRMED' };
        }
        return a;
      })
    );
    triggerToast('Alert confirmed');
  };

  // Analyze Packet Payload with Gemini
  const handleAnalyzePayload = async (anomaly: AnomalyEvent) => {
    setActiveTab('overview');
    triggerToast(`Analyzing ${anomaly.event}...`);
    setIsCopilotLoading(true);

    try {
      const res = await fetch('/api/analyze-packet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ anomaly }),
      });
      const data = await res.json();

      setChatMessages((prev) => [
        ...prev,
        {
          id: `msg-usr-${Date.now()}`,
          sender: 'user',
          text: `Analyze payload snippet for ${anomaly.event} (${anomaly.ip})`,
          timestamp: 'Just now',
        },
        {
          id: `msg-bot-${Date.now()}`,
          sender: 'bot',
          text: data.analysis || 'Analysis complete. Recommended action: Add IP to WAF blocklist.',
          timestamp: 'Just now',
        },
      ]);
    } catch {
      setChatMessages((prev) => [
        ...prev,
        {
          id: `msg-bot-${Date.now()}`,
          sender: 'bot',
          text: `Analysis for ${anomaly.event}: Suspected malicious scanning payload from ${anomaly.ip}. Recommended action: Block IP in WAF rules.`,
          timestamp: 'Just now',
        },
      ]);
    } finally {
      setIsCopilotLoading(false);
    }
  };

  // Send Message to Orbit AI Copilot
  const handleSendMessage = async (text: string) => {
    const userMsg: ChatMessage = {
      id: `msg-user-${Date.now()}`,
      sender: 'user',
      text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setChatMessages((prev) => [...prev, userMsg]);
    setIsCopilotLoading(true);

    try {
      const res = await fetch('/api/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: text,
          context: {
            throughput,
            activeFlows,
            threatsCount,
            mitigatedCount,
            threatVector,
            topAnomaly: anomalies[0],
          },
          history: chatMessages.slice(-4),
        }),
      });

      const data = await res.json();

      const botMsg: ChatMessage = {
        id: `msg-bot-${Date.now()}`,
        sender: 'bot',
        text: data.reply || `Correlated telemetry logs for "${text}". All edge gateways operating within threshold.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setChatMessages((prev) => [...prev, botMsg]);
    } catch (err: any) {
      setChatMessages((prev) => [
        ...prev,
        {
          id: `msg-bot-${Date.now()}`,
          sender: 'bot',
          text: `Correlated telemetry logs for "${text}". All edge gateways operating within threshold.`,
          timestamp: 'Just now',
        },
      ]);
    } finally {
      setIsCopilotLoading(false);
    }
  };

  // Rule Toggle & Create
  const handleToggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) =>
        r.id === id ? { ...r, status: r.status === 'ACTIVE' ? 'PAUSED' : 'ACTIVE' } : r
      )
    );
    triggerToast('Rule enforcement updated');
  };

  const handleAddRule = (newRule: SecurityRule) => {
    setRules((prev) => [newRule, ...prev]);
    triggerToast(`Rule "${newRule.name}" deployed to edge`);
  };

  // Filter anomalies based on search bar
  const filteredAnomalies = anomalies.filter(
    (a) =>
      a.event.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.asset.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="flex min-h-screen bg-[#e8eceb] font-sans text-[#253835]">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={handleTabChange}
        operator={operator}
        onOpenRoleModal={() => setIsRoleModalOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1 p-8 md:p-10 max-w-[1600px] w-full mx-auto overflow-x-hidden">
        <TopHeader
          activeTab={activeTab}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          onRunSimulation={handleRunSimulation}
          isSimulating={isSimulating}
          operator={operator}
          onOpenRoleModal={() => setIsRoleModalOpen(true)}
        />

        {/* Tab View Switching */}
        {activeTab === 'overview' && (
          <OverviewView
            throughput={throughput}
            activeFlows={activeFlows}
            threatsCount={threatsCount}
            mitigatedCount={mitigatedCount}
            trafficData={trafficData}
            isLive={isLiveTraffic}
            onToggleLive={() => setIsLiveTraffic(!isLiveTraffic)}
            threatVector={threatVector}
            onIsolateVector={handleIsolateVector}
            anomalies={filteredAnomalies}
            onReviewAnomaly={handleReviewAnomaly}
            onAnalyzePayload={handleAnalyzePayload}
            chatMessages={chatMessages}
            onSendMessage={handleSendMessage}
            isCopilotLoading={isCopilotLoading}
          />
        )}

        {activeTab === 'traffic' && <LiveTrafficView />}

        {activeTab === 'threats' && <ThreatIntelView />}

        {activeTab === 'alerts' && (
          <AlertsConsoleView
            anomalies={filteredAnomalies}
            onReviewAnomaly={handleReviewAnomaly}
            onAnalyzePayload={handleAnalyzePayload}
          />
        )}

        {activeTab === 'rules' && (
          <RulesEngineView
            rules={rules}
            onToggleRule={handleToggleRule}
            onAddRule={handleAddRule}
          />
        )}

        {activeTab === 'replay' && <AttackReplayView />}

        {activeTab === 'reports' && <ReportsView />}
      </main>

      {/* Role Profile Switcher Modal */}
      <RoleSwitcherModal
        isOpen={isRoleModalOpen}
        onClose={() => setIsRoleModalOpen(false)}
        currentOperator={operator}
        onSelectOperator={(op) => {
          setOperator(op);
          triggerToast(`Operator switched to ${op.name}`);
        }}
      />

      {/* Bottom Floating Toast */}
      <Toast message={toastMessage} />
    </div>
  );
}
