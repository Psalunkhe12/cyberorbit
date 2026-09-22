import React from 'react';
import { MetricsBar } from '../components/MetricsBar';
import { TrafficVelocityCard } from '../components/TrafficVelocityCard';
import { ThreatVectorRadar } from '../components/ThreatVectorRadar';
import { PriorityTriageStream } from '../components/PriorityTriageStream';
import { OrbitCopilotCard } from '../components/OrbitCopilotCard';
import { TrafficPoint, ThreatVector, AnomalyEvent, ChatMessage } from '../types';

interface OverviewViewProps {
  throughput: string;
  activeFlows: number;
  threatsCount: number;
  mitigatedCount: number;
  trafficData: TrafficPoint[];
  isLive: boolean;
  onToggleLive: () => void;
  threatVector: ThreatVector;
  onIsolateVector: () => void;
  anomalies: AnomalyEvent[];
  onReviewAnomaly: (id: string) => void;
  onAnalyzePayload: (anomaly: AnomalyEvent) => void;
  chatMessages: ChatMessage[];
  onSendMessage: (text: string) => void;
  isCopilotLoading: boolean;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  throughput,
  activeFlows,
  threatsCount,
  mitigatedCount,
  trafficData,
  isLive,
  onToggleLive,
  threatVector,
  onIsolateVector,
  anomalies,
  onReviewAnomaly,
  onAnalyzePayload,
  chatMessages,
  onSendMessage,
  isCopilotLoading,
}) => {
  return (
    <div className="flex flex-col gap-5">
      {/* Metrics Row */}
      <MetricsBar
        throughput={throughput}
        activeFlows={activeFlows}
        threatsCount={threatsCount}
        mitigatedCount={mitigatedCount}
      />

      {/* Row Main: Traffic Velocity + Threat Vector Radar */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2">
          <TrafficVelocityCard
            data={trafficData}
            onToggleLive={onToggleLive}
            isLive={isLive}
          />
        </div>
        <div className="lg:col-span-1">
          <ThreatVectorRadar
            vector={threatVector}
            onIsolateVector={onIsolateVector}
          />
        </div>
      </section>

      {/* Row Bottom: Priority Triage Stream + Orbit AI Copilot */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2">
          <PriorityTriageStream
            anomalies={anomalies}
            onReviewAnomaly={onReviewAnomaly}
            onAnalyzePayload={onAnalyzePayload}
          />
        </div>
        <div className="lg:col-span-1">
          <OrbitCopilotCard
            messages={chatMessages}
            onSendMessage={onSendMessage}
            isLoading={isCopilotLoading}
          />
        </div>
      </section>
    </div>
  );
};
