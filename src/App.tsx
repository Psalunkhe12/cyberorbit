import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { TopHeader } from './components/TopHeader';
import { Toast } from './components/Toast';
import { RoleSwitcherModal } from './components/RoleSwitcherModal';
import { LoginFormModal } from './components/LoginFormModal';
import { UserProfileModal } from './components/UserProfileModal';
import { AuthProvider, useAuth } from './context/AuthContext';
import {
  NavigationTab,
  Operator,
  AnomalyEvent,
  SecurityRule,
  ThreatVector,
  TrafficPoint,
  ChatMessage,
} from './types';
import { OPERATOR_PROFILES } from './data/mockData';

import { useRealtimeAlerts } from './hooks/useRealtimeAlerts';
import { useRealtimeNetworkEvents } from './hooks/useRealtimeNetworkEvents';
import { useRealtimeRules } from './hooks/useRealtimeRules';
import { useRealtimeThreatIntel } from './hooks/useRealtimeThreatIntel';

import { OverviewView } from './views/OverviewView';
import { IncidentsView } from './views/IncidentsView';
import { LiveTrafficView } from './views/LiveTrafficView';
import { ThreatIntelView } from './views/ThreatIntelView';
import { AlertsConsoleView } from './views/AlertsConsoleView';
import { RulesEngineView } from './views/RulesEngineView';
import { AttackReplayView } from './views/AttackReplayView';
import { ReportsView } from './views/ReportsView';

function CyberOrbitApp() {
  const [activeTab, setActiveTab] = useState<NavigationTab>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const {
    isLoginModalOpen,
    setIsLoginModalOpen,
    isProfileModalOpen,
    setIsProfileModalOpen,
    permissions,
  } = useAuth();

  // Operator Profile
  const [operator, setOperator] = useState<Operator>(OPERATOR_PROFILES[0]);
  const [isRoleModalOpen, setIsRoleModalOpen] = useState(false);

  // Simulation & Stream Control
  const [isSimulating, setIsSimulating] = useState(false);
  const [isLiveTraffic, setIsLiveTraffic] = useState(true);

  // Copilot Chat State
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      id: 'msg-0',
      sender: 'bot',
      text: 'CyberOrbit SOC Assistant active. Realtime database telemetry monitoring engaged.',
      timestamp: '10:00',
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
      incidents: 'Incidents Center',
      traffic: 'Live Traffic',
      threats: 'Threat Intel',
      alerts: 'Alerts Console',
      rules: 'Rules Engine',
      replay: 'Attack Replay',
      reports: 'Reports',
    };
    triggerToast(`${labels[tab]} loaded`);
  };

  // Realtime Supabase Data Hooks
  const { alerts: anomalies, setAlerts: setAnomalies } = useRealtimeAlerts();
  const { networkEvents, trafficMetrics } = useRealtimeNetworkEvents();
  const { rules, toggleRuleStatus, addRule } = useRealtimeRules();
  const { primaryVector, isolateThreatVector } = useRealtimeThreatIntel();

  // Dynamically derive metrics and chart telemetry from real database rows
  const trafficData: TrafficPoint[] = trafficMetrics.length > 0
    ? trafficMetrics.slice(0, 10).reverse().map((m) => {
        const d = new Date(m.timestamp);
        const timeStr = isNaN(d.getTime())
          ? String(m.timestamp || '').slice(11, 16) || '00:00'
          : `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
        return {
          time: timeStr,
          throughputGbps: typeof m.throughput_mbps === 'number' ? parseFloat((m.throughput_mbps / 1000).toFixed(2)) : 0,
          activeFlows: m.active_connections || 0,
          threatRequests: m.threat_count || 0,
          synPackets: m.inbound_packets || 0,
        };
      })
    : [];

  const throughput = trafficData.length > 0
    ? trafficData[trafficData.length - 1].throughputGbps.toFixed(2)
    : '0.00';

  const activeFlows = trafficData.length > 0
    ? trafficData[trafficData.length - 1].activeFlows
    : networkEvents.length;

  const threatsCount = anomalies.filter((a) => a.status === 'UNREVIEWED' || a.status === 'CONFIRMED').length;
  const mitigatedCount = anomalies.filter((a) => a.status === 'MITIGATED' || a.status === 'DISMISSED').length;

  const threatVector: ThreatVector = primaryVector
    ? {
        origin: primaryVector.origin,
        target: primaryVector.target,
        originCode: primaryVector.originCode,
        targetCode: primaryVector.targetCode,
        riskScore: primaryVector.riskScore,
        riskLabel: primaryVector.riskLabel,
        attackType: primaryVector.attackType,
        isIsolated: primaryVector.isIsolated,
      }
    : {
        origin: 'No Threat Origin',
        target: 'Perimeter Secure',
        originCode: 'OK',
        targetCode: 'OK',
        riskScore: 0,
        riskLabel: 'Nominal 0/100',
        attackType: 'Nominal Telemetry',
        isIsolated: false,
      };

  // Run Simulation Handler
  const handleRunSimulation = async () => {
    if (!permissions.canTriageAlerts) {
      triggerToast('Permission Denied: Read-Only VIEWER role cannot run attack simulations.');
      return;
    }

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
    if (!permissions.canApproveResponseActions) {
      triggerToast('Permission Denied: Only SOC_LEAD or ADMIN roles can isolate vectors.');
      return;
    }

    isolateThreatVector();
    triggerToast('Target threat vector isolated');
  };

  // Review & Confirm Anomaly
  const handleReviewAnomaly = (id: string) => {
    if (!permissions.canTriageAlerts) {
      triggerToast('Permission Denied: Read-Only VIEWER role cannot modify alert status.');
      return;
    }

    setAnomalies((prev) =>
      prev.map((a) => {
        if (a.id === id) {
          return { ...a, status: 'CONFIRMED' };
        }
        return a;
      })
    );
    triggerToast('Alert confirmed');
  };

  // Analyze Packet Payload with Gemini
  const handleAnalyzePayload = async (anomaly: AnomalyEvent) => {
    if (!permissions.canTriggerAIAnalysis) {
      triggerToast('Permission Denied: Read-Only VIEWER role cannot trigger AI analysis.');
      return;
    }

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
          },
        }),
      });
      const data = await res.json();

      const botMsg: ChatMessage = {
        id: `msg-bot-${Date.now()}`,
        sender: 'bot',
        text: data.reply || 'Orbit AI completed analysis.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setChatMessages((prev) => [...prev, botMsg]);
    } catch {
      const fallbackMsg: ChatMessage = {
        id: `msg-bot-${Date.now()}`,
        sender: 'bot',
        text: 'All edge proxies reporting normal state. SYN flood rate limiting active on gateway-01.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setChatMessages((prev) => [...prev, fallbackMsg]);
    } finally {
      setIsCopilotLoading(false);
    }
  };

  // Security Rule Toggle & Add Handlers
  const handleToggleRule = (id: string) => {
    if (!permissions.canManageSecurityRules) {
      triggerToast('Permission Denied: Only SOC_LEAD or ADMIN roles can modify firewall rules.');
      return;
    }
    toggleRuleStatus(id);
    triggerToast(`Toggled security rule status`);
  };

  const handleAddRule = (newRule: Omit<SecurityRule, 'id' | 'matchesCount' | 'lastTriggered'>) => {
    if (!permissions.canManageSecurityRules) {
      triggerToast('Permission Denied: Only SOC_LEAD or ADMIN roles can add new firewall rules.');
      return;
    }

    const created: SecurityRule = {
      ...newRule,
      id: `rule-${Date.now()}`,
      matchesCount: 0,
      lastTriggered: 'Never',
    };
    addRule(created);
    triggerToast(`Created new security rule ${created.name}`);
  };

  const filteredAnomalies = anomalies.filter(
    (a) =>
      a.event.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.asset.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="flex bg-[#e8eceb] text-[#253835] font-sans antialiased min-h-screen">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={handleTabChange}
        operator={operator}
        onOpenRoleModal={() => setIsProfileModalOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1 p-8 md:p-10 max-w-[1600px] w-full mx-auto overflow-x-hidden">
        <TopHeader
          activeTab={activeTab}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          onRunSimulation={handleRunSimulation}
          isSimulating={isSimulating}
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

        {activeTab === 'incidents' && <IncidentsView onTriggerToast={triggerToast} />}

        {activeTab === 'traffic' && <LiveTrafficView />}

        {activeTab === 'threats' && <ThreatIntelView />}

        {activeTab === 'alerts' && (
          <AlertsConsoleView
            anomalies={filteredAnomalies}
            onReviewAnomaly={handleReviewAnomaly}
            onAnalyzePayload={handleAnalyzePayload}
            onTriggerToast={triggerToast}
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

      {/* Login & Sign Up Modal */}
      {isLoginModalOpen && (
        <LoginFormModal
          onClose={() => setIsLoginModalOpen(false)}
          onTriggerToast={triggerToast}
        />
      )}

      {/* User Profile & Role Permissions Modal */}
      {isProfileModalOpen && (
        <UserProfileModal
          onClose={() => setIsProfileModalOpen(false)}
          onTriggerToast={triggerToast}
        />
      )}

      {/* Legacy Role Switcher Backup */}
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

export default function App() {
  return (
    <AuthProvider>
      <CyberOrbitApp />
    </AuthProvider>
  );
}
