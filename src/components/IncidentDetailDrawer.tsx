import React from 'react';
import { CyberIncident, IncidentStatusType, SeverityLevel } from '../types';
import { logAuditAction } from '../lib/auditLogger';
import { useAuth } from '../context/AuthContext';
import {
  X,
  Shield,
  Clock,
  UserCheck,
  CheckCircle2,
  AlertCircle,
  Activity,
  Layers,
  Terminal,
  User,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';

interface IncidentDetailDrawerProps {
  incident: CyberIncident | null;
  onClose: () => void;
  onUpdateStatus: (incidentId: string, status: IncidentStatusType) => void;
  onAssignAnalyst: (incidentId: string, analystName: string) => void;
  onTriggerToast: (msg: string) => void;
}

const ANALYSTS = [
  'Sarah Chen (SOC Lead)',
  'Alex Mercer (Senior Threat Hunter)',
  'Elena Rostova (Incident Responder)',
  'Marcus Vance (SecOps Engineer)',
  'Unassigned',
];

export const IncidentDetailDrawer: React.FC<IncidentDetailDrawerProps> = ({
  incident,
  onClose,
  onUpdateStatus,
  onAssignAnalyst,
  onTriggerToast,
}) => {
  const { profile } = useAuth();
  if (!incident) return null;

  const getSeverityStyle = (severity: SeverityLevel) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-[#fde8e8] text-[#d94b4b] border-[#f8b4b4]';
      case 'HIGH':
        return 'bg-[#fdf3e1] text-[#b8821a] border-[#f6d79b]';
      case 'MEDIUM':
        return 'bg-[#e3f2fd] text-[#1976d2] border-[#90caf9]';
      case 'LOW':
        return 'bg-[#e8f5e9] text-[#2d9d78] border-[#a5d6a7]';
    }
  };

  const getStatusStyle = (status: IncidentStatusType) => {
    switch (status) {
      case 'OPEN':
        return 'bg-[#d94b4b]/15 text-[#d94b4b] border-[#d94b4b]/30';

      case 'ACKNOWLEDGED':
        return 'bg-[#d49b28]/15 text-[#d49b28] border-[#d49b28]/30';
      case 'INVESTIGATING':
        return 'bg-[#1976d2]/15 text-[#1976d2] border-[#1976d2]/30';
      case 'CONTAINED':
        return 'bg-[#8e24aa]/15 text-[#8e24aa] border-[#8e24aa]/30';
      case 'RESOLVED':
      case 'MITIGATED':
      case 'CONFIRMED':
        return 'bg-[#2d9d78]/15 text-[#2d9d78] border-[#2d9d78]/30';
      case 'FALSE_POSITIVE':
      case 'DISMISSED':
        return 'bg-[#78909c]/15 text-[#78909c] border-[#78909c]/30';
      default:
        return 'bg-[#334d4a]/15 text-[#334d4a] border-[#334d4a]/30';
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 75) return 'text-[#d94b4b] bg-[#fde8e8] border-[#f8b4b4]';
    if (score >= 50) return 'text-[#b8821a] bg-[#fdf3e1] border-[#f6d79b]';
    if (score >= 25) return 'text-[#1976d2] bg-[#e3f2fd] border-[#90caf9]';
    return 'text-[#2d9d78] bg-[#e8f5e9] border-[#a5d6a7]';
  };

  const handleAcknowledge = () => {
    onUpdateStatus(incident.id, 'ACKNOWLEDGED');
    logAuditAction({
      user: profile?.email || 'ANALYST',
      action: 'INCIDENT_UPDATED',
      entity: incident.id,
      old_value: { status: incident.status },
      new_value: { status: 'ACKNOWLEDGED' },
    });
    onTriggerToast(`Incident ${incident.id} marked as ACKNOWLEDGED`);
  };

  const handleResolve = () => {
    onUpdateStatus(incident.id, 'RESOLVED');
    logAuditAction({
      user: profile?.email || 'ANALYST',
      action: 'INCIDENT_RESOLVED',
      entity: incident.id,
      old_value: { status: incident.status },
      new_value: { status: 'RESOLVED' },
    });
    onTriggerToast(`Incident ${incident.id} marked as RESOLVED`);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/45 backdrop-blur-xs flex justify-end animate-in fade-in duration-200">
      <div className="bg-white w-full max-w-3xl h-full flex flex-col shadow-2xl border-l border-[#d4deda] overflow-hidden">
        {/* Header */}
        <div className="p-6 bg-[#334d4a] text-white flex justify-between items-start shrink-0">
          <div>
            <div className="flex items-center gap-2.5 mb-2">
              <span className="font-mono-code text-[11px] bg-white/10 text-white/90 px-2.5 py-0.5 rounded-md font-bold tracking-wide">
                {incident.id}
              </span>
              <span
                className={`text-[10px] font-extrabold px-2.5 py-0.5 rounded-full border uppercase ${getSeverityStyle(
                  incident.severity
                )}`}
              >
                {incident.severity}
              </span>
              <span
                className={`text-[10px] font-extrabold px-2.5 py-0.5 rounded-full border uppercase ${getStatusStyle(
                  incident.status
                )}`}
              >
                {incident.status}
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white tracking-tight">
              {incident.title}
            </h2>
            <p className="text-xs text-white/70 mt-1">
              Correlated Attack Vector: <span className="text-[#d49b28] font-semibold">{incident.attack_vector}</span>
            </p>
          </div>

          <button
            onClick={onClose}
            className="text-white/70 hover:text-white bg-white/10 hover:bg-white/20 p-2 rounded-full border-none cursor-pointer transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-[#e8eceb]/40">
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {/* Risk Score */}
            <div className="bg-white p-3.5 rounded-2xl border border-[#d4deda] shadow-xs flex flex-col justify-between">
              <span className="text-[10px] font-bold text-[#6c8582] uppercase tracking-wider block">
                Risk Score
              </span>
              <div className="flex items-baseline gap-1.5 mt-1">
                <span
                  className={`text-2xl font-extrabold font-display px-2 py-0.5 rounded-lg border ${getRiskScoreColor(
                    incident.risk_score || 70
                  )}`}
                >
                  {incident.risk_score || 70}
                </span>
                <span className="text-xs text-[#6c8582] font-semibold">/100</span>
              </div>
            </div>

            {/* Source IP */}
            <div className="bg-white p-3.5 rounded-2xl border border-[#d4deda] shadow-xs flex flex-col justify-between">
              <span className="text-[10px] font-bold text-[#6c8582] uppercase tracking-wider block">
                Source IP
              </span>
              <span className="font-mono-code text-sm font-bold text-[#334d4a] truncate mt-1">
                {incident.source_ip}
              </span>
            </div>

            {/* Target Asset */}
            <div className="bg-white p-3.5 rounded-2xl border border-[#d4deda] shadow-xs flex flex-col justify-between">
              <span className="text-[10px] font-bold text-[#6c8582] uppercase tracking-wider block">
                Target Asset
              </span>
              <span className="font-mono-code text-xs font-bold text-[#253835] truncate mt-1">
                {incident.target_asset}
              </span>
            </div>

            {/* Correlated Alerts */}
            <div className="bg-white p-3.5 rounded-2xl border border-[#d4deda] shadow-xs flex flex-col justify-between">
              <span className="text-[10px] font-bold text-[#6c8582] uppercase tracking-wider block">
                Alert Count
              </span>
              <div className="flex items-center gap-1.5 mt-1 text-sm font-bold text-[#334d4a]">
                <Layers className="w-4 h-4 text-[#d49b28]" />
                <span>{incident.alert_count || incident.related_alerts?.length || 1} Alerts</span>
              </div>
            </div>
          </div>

          {/* Quick Action Control Panel */}
          <div className="bg-white p-5 rounded-2xl border border-[#d4deda] shadow-xs">
            <div className="flex flex-wrap items-center justify-between gap-4">
              {/* Status Action Buttons */}
              <div className="flex items-center gap-2">
                <button
                  onClick={handleAcknowledge}
                  disabled={incident.status === 'ACKNOWLEDGED'}
                  className={`px-4 py-2 rounded-xl text-xs font-bold border-none cursor-pointer flex items-center gap-1.5 transition-all ${
                    incident.status === 'ACKNOWLEDGED'
                      ? 'bg-[#d49b28]/20 text-[#d49b28] cursor-default'
                      : 'bg-[#d49b28] hover:bg-[#b8821a] text-white shadow-sm'
                  }`}
                >
                  <UserCheck className="w-4 h-4" />
                  <span>Acknowledge</span>
                </button>

                <button
                  onClick={handleResolve}
                  disabled={incident.status === 'RESOLVED'}
                  className={`px-4 py-2 rounded-xl text-xs font-bold border-none cursor-pointer flex items-center gap-1.5 transition-all ${
                    incident.status === 'RESOLVED'
                      ? 'bg-[#2d9d78]/20 text-[#2d9d78] cursor-default'
                      : 'bg-[#2d9d78] hover:bg-[#237c5f] text-white shadow-sm'
                  }`}
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Resolve</span>
                </button>

                {/* Status Dropdown Selector */}
                <select
                  value={incident.status}
                  onChange={(e) => {
                    const st = e.target.value as IncidentStatusType;
                    onUpdateStatus(incident.id, st);
                    onTriggerToast(`Status changed to ${st}`);
                  }}
                  className="bg-[#f0f5f3] text-[#253835] text-xs font-bold py-2 px-3 rounded-xl border border-[#d4deda] outline-none cursor-pointer"
                >
                  <option value="OPEN">Set Status: OPEN</option>
                  <option value="ACKNOWLEDGED">Set Status: ACKNOWLEDGED</option>
                  <option value="INVESTIGATING">Set Status: INVESTIGATING</option>
                  <option value="CONTAINED">Set Status: CONTAINED</option>
                  <option value="RESOLVED">Set Status: RESOLVED</option>
                  <option value="FALSE_POSITIVE">Set Status: FALSE_POSITIVE</option>
                </select>
              </div>

              {/* Analyst Assignment Dropdown */}
              <div className="flex items-center gap-2">
                <User className="w-4 h-4 text-[#6c8582]" />
                <span className="text-xs font-bold text-[#6c8582]">Assignee:</span>
                <select
                  value={incident.assigned_to || 'Unassigned'}
                  onChange={(e) => {
                    onAssignAnalyst(incident.id, e.target.value);
                    onTriggerToast(`Assigned to ${e.target.value}`);
                  }}
                  className="bg-[#334d4a]/10 text-[#334d4a] text-xs font-bold py-2 px-3 rounded-xl border border-[#334d4a]/20 outline-none cursor-pointer"
                >
                  {ANALYSTS.map((name) => (
                    <option key={name} value={name}>
                      {name}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Evidence Summary */}
          {incident.summary && (
            <div className="bg-white p-5 rounded-2xl border border-[#d4deda] shadow-xs">
              <h3 className="text-xs font-bold text-[#6c8582] uppercase tracking-wider mb-2 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#334d4a]" />
                <span>Incident Executive Summary</span>
              </h3>
              <p className="text-xs text-[#253835] font-medium leading-relaxed bg-[#f0f5f3] p-3.5 rounded-xl border border-[#d4deda]/50">
                {incident.summary}
              </p>
            </div>
          )}

          {/* Incident Timeline */}
          <div className="bg-white p-5 rounded-2xl border border-[#d4deda] shadow-xs">
            <h3 className="text-xs font-bold text-[#6c8582] uppercase tracking-wider mb-4 flex items-center gap-2">
              <Clock className="w-4 h-4 text-[#334d4a]" />
              <span>Incident Correlation Timeline</span>
            </h3>

            <div className="relative border-l-2 border-[#d4deda] ml-3 pl-5 space-y-4">
              <div className="relative">
                <div className="absolute -left-[27px] top-0.5 w-3 h-3 rounded-full bg-[#d94b4b] border-2 border-white shadow-xs" />
                <div className="flex items-center justify-between text-xs font-bold text-[#253835]">
                  <span>Initial Threat Vector Triggered</span>
                  <span className="font-mono-code text-[11px] text-[#6c8582]">
                    {new Date(incident.first_seen_at).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-xs text-[#6c8582] mt-0.5">
                  Anomaly detected from <span className="font-mono-code">{incident.source_ip}</span> targeting asset{' '}
                  <span className="font-mono-code">{incident.target_asset}</span>.
                </p>
              </div>

              <div className="relative">
                <div className="absolute -left-[27px] top-0.5 w-3 h-3 rounded-full bg-[#d49b28] border-2 border-white shadow-xs" />
                <div className="flex items-center justify-between text-xs font-bold text-[#253835]">
                  <span>Multi-Rule Telemetry Grouped</span>
                  <span className="font-mono-code text-[11px] text-[#6c8582]">
                    {new Date(incident.last_seen_at).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-xs text-[#6c8582] mt-0.5">
                  Correlated {incident.rule_ids?.join(', ') || 'RL-2001'} rule detections into unified campaign.
                </p>
              </div>

              <div className="relative">
                <div className="absolute -left-[27px] top-0.5 w-3 h-3 rounded-full bg-[#334d4a] border-2 border-white shadow-xs" />
                <div className="flex items-center justify-between text-xs font-bold text-[#253835]">
                  <span>Status: {incident.status}</span>
                  <span className="font-mono-code text-[11px] text-[#6c8582]">Current</span>
                </div>
                <p className="text-xs text-[#6c8582] mt-0.5">
                  Assigned analyst: <span className="font-semibold text-[#334d4a]">{incident.assigned_to || 'Unassigned'}</span>.
                </p>
              </div>
            </div>
          </div>

          {/* Related Correlated Alerts Table */}
          <div className="bg-white p-5 rounded-2xl border border-[#d4deda] shadow-xs">
            <h3 className="text-xs font-bold text-[#6c8582] uppercase tracking-wider mb-3 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-[#d49b28]" />
              <span>Correlated Related Alerts ({incident.related_alerts?.length || 1})</span>
            </h3>

            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[#d4deda] text-left text-[10px] font-bold text-[#6c8582] uppercase">
                    <th className="py-2 px-2">RULE ID</th>
                    <th className="py-2 px-2">ALERT NAME</th>
                    <th className="py-2 px-2">SEVERITY</th>
                    <th className="py-2 px-2">EVIDENCE</th>
                    <th className="py-2 px-2 text-right">TIME</th>
                  </tr>
                </thead>
                <tbody>
                  {incident.related_alerts && incident.related_alerts.length > 0 ? (
                    incident.related_alerts.map((alt) => (
                      <tr key={alt.id} className="border-b border-[#edf2f0] hover:bg-[#f0f5f3]">
                        <td className="py-2.5 px-2 font-mono-code font-bold text-[#334d4a]">
                          {alt.rule_id}
                        </td>
                        <td className="py-2.5 px-2 font-semibold text-[#253835]">
                          {alt.rule_name}
                        </td>
                        <td className="py-2.5 px-2">
                          <span
                            className={`text-[9px] font-extrabold px-2 py-0.5 rounded-full uppercase ${getSeverityStyle(
                              alt.severity
                            )}`}
                          >
                            {alt.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-2 text-[#6c8582] max-w-xs truncate font-mono-code text-[11px]">
                          {alt.evidence}
                        </td>
                        <td className="py-2.5 px-2 text-right font-mono-code text-[11px] text-[#6c8582]">
                          {new Date(alt.timestamp).toLocaleTimeString()}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr className="border-b border-[#edf2f0]">
                      <td className="py-2.5 px-2 font-mono-code font-bold text-[#334d4a]">
                        {incident.rule_ids?.[0] || 'RL-2001'}
                      </td>
                      <td className="py-2.5 px-2 font-semibold text-[#253835]">
                        {incident.title}
                      </td>
                      <td className="py-2.5 px-2">
                        <span
                          className={`text-[9px] font-extrabold px-2 py-0.5 rounded-full uppercase ${getSeverityStyle(
                            incident.severity
                          )}`}
                        >
                          {incident.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-2 text-[#6c8582] max-w-xs truncate font-mono-code text-[11px]">
                        {incident.evidence_summary || 'Correlated security telemetry matches'}
                      </td>
                      <td className="py-2.5 px-2 text-right font-mono-code text-[11px] text-[#6c8582]">
                        {new Date(incident.updated_at).toLocaleTimeString()}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
