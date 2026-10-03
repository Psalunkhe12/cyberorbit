import React, { useState } from 'react';
import { CyberIncident, IncidentStatusType, SeverityLevel } from '../types';
import { useRealtimeIncidents } from '../hooks/useRealtimeIncidents';
import { IncidentDetailDrawer } from '../components/IncidentDetailDrawer';
import { HumanInTheLoopResponsePanel } from '../components/HumanInTheLoopResponsePanel';
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  UserCheck,
  Activity,
  Layers,
  AlertTriangle,
  Clock,
  User,
  ExternalLink,
} from 'lucide-react';

interface IncidentsViewProps {
  onTriggerToast: (msg: string) => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({ onTriggerToast }) => {
  const {
    incidents,
    loading,
    isLive,
    updateIncidentStatus,
    assignAnalyst,
  } = useRealtimeIncidents();

  const [selectedIncident, setSelectedIncident] = useState<CyberIncident | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

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

  // Filter logic
  const filteredIncidents = incidents.filter((inc) => {
    const matchesSearch =
      inc.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      inc.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      inc.source_ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      inc.target_asset.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesStatus =
      statusFilter === 'ALL' || inc.status.toUpperCase() === statusFilter.toUpperCase();
    const matchesSeverity =
      severityFilter === 'ALL' || inc.severity.toUpperCase() === severityFilter.toUpperCase();

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  // Calculate Metrics
  const totalCount = incidents.length;
  const criticalCount = incidents.filter((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH').length;
  const openCount = incidents.filter((i) => i.status === 'OPEN' || i.status === 'UNREVIEWED').length;
  const resolvedCount = incidents.filter(
    (i) => i.status === 'RESOLVED' || i.status === 'MITIGATED' || i.status === 'CONFIRMED'
  ).length;

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Top Banner Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-5 rounded-[24px] border border-[#d4deda] shadow-xs flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold text-[#6c8582] uppercase tracking-wider block mb-1">
              Total Correlated Incidents
            </span>
            <span className="text-2xl font-extrabold font-display text-[#253835]">
              {totalCount}
            </span>
          </div>
          <div className="w-10 h-10 rounded-2xl bg-[#334d4a]/10 text-[#334d4a] grid place-items-center">
            <Layers className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-white p-5 rounded-[24px] border border-[#d4deda] shadow-xs flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold text-[#6c8582] uppercase tracking-wider block mb-1">
              Active Critical / High
            </span>
            <span className="text-2xl font-extrabold font-display text-[#d94b4b]">
              {criticalCount}
            </span>
          </div>
          <div className="w-10 h-10 rounded-2xl bg-[#fde8e8] text-[#d94b4b] grid place-items-center">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-white p-5 rounded-[24px] border border-[#d4deda] shadow-xs flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold text-[#6c8582] uppercase tracking-wider block mb-1">
              Needs Review / Open
            </span>
            <span className="text-2xl font-extrabold font-display text-[#d49b28]">
              {openCount}
            </span>
          </div>
          <div className="w-10 h-10 rounded-2xl bg-[#fdf3e1] text-[#d49b28] grid place-items-center">
            <Clock className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-white p-5 rounded-[24px] border border-[#d4deda] shadow-xs flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold text-[#6c8582] uppercase tracking-wider block mb-1">
              Resolved / Mitigated
            </span>
            <span className="text-2xl font-extrabold font-display text-[#2d9d78]">
              {resolvedCount}
            </span>
          </div>
          <div className="w-10 h-10 rounded-2xl bg-[#e8f5e9] text-[#2d9d78] grid place-items-center">
            <CheckCircle2 className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Control Bar: Filters & Search */}
      <div className="bg-white p-5 rounded-[28px] border border-[#d4deda] shadow-xs flex flex-wrap items-center justify-between gap-4">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-[#6c8582] absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search incident ID, IP, target asset, or attack vector..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-[#f0f5f3] rounded-xl text-xs font-semibold text-[#253835] placeholder-[#6c8582] outline-none border border-[#d4deda] focus:border-[#334d4a]"
          />
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 bg-[#f0f5f3] px-3 py-1.5 rounded-xl border border-[#d4deda]">
            <Filter className="w-3.5 h-3.5 text-[#6c8582]" />
            <span className="text-[11px] font-bold text-[#6c8582] uppercase">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-transparent text-xs font-bold text-[#253835] outline-none cursor-pointer"
            >
              <option value="ALL">ALL STATUSES</option>
              <option value="OPEN">OPEN</option>
              <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="CONTAINED">CONTAINED</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 bg-[#f0f5f3] px-3 py-1.5 rounded-xl border border-[#d4deda]">
            <span className="text-[11px] font-bold text-[#6c8582] uppercase">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-xs font-bold text-[#253835] outline-none cursor-pointer"
            >
              <option value="ALL">ALL SEVERITIES</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div className="flex items-center gap-2 text-xs font-bold text-[#334d4a] px-3 py-2 rounded-xl bg-[#334d4a]/10">
            <span className={`w-2 h-2 rounded-full ${isLive ? 'bg-[#2d9d78] animate-pulse' : 'bg-[#d49b28]'}`} />
            <span>{isLive ? 'REALTIME SYNC ON' : 'POLLING ACTIVE'}</span>
          </div>
        </div>
      </div>

      {/* Human-in-the-Loop AI Response Control Panel */}
      <HumanInTheLoopResponsePanel onTriggerToast={onTriggerToast} />

      {/* Main Incident List Table */}
      <div className="bg-white rounded-[28px] p-6 border border-[#d4deda] shadow-xs">
        <div className="flex justify-between items-center mb-4">
          <div className="flex items-center gap-3">
            <ShieldAlert className="w-5 h-5 text-[#334d4a]" />
            <h2 className="font-display text-lg font-bold text-[#253835]">
              Active Correlated Security Incidents
            </h2>
          </div>
          <span className="text-[11px] font-bold px-3 py-1 rounded-full bg-[#334d4a]/10 text-[#334d4a]">
            SHOWING ({filteredIncidents.length})
          </span>
        </div>

        <div className="overflow-x-auto">
          {filteredIncidents.length === 0 ? (
            <div className="py-12 px-4 text-center bg-[#f8faf9] rounded-2xl border border-dashed border-[#c2d1cc]">
              <CheckCircle2 className="w-8 h-8 text-[#2d9d78] mx-auto mb-2 opacity-70" />
              <p className="text-xs font-bold text-[#334d4a] m-0">No Cyber Incidents Found</p>
              <p className="text-[11px] text-[#6c8582] mt-1 m-0">
                No incidents in database match status filter '{statusFilter}' and severity filter '{severityFilter}'.
              </p>
            </div>
          ) : (
            <table className="w-full border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#d4deda] text-left text-[10px] font-bold text-[#6c8582] uppercase tracking-wider">
                  <th className="py-3 px-3">INCIDENT</th>
                  <th className="py-3 px-3">SEVERITY</th>
                  <th className="py-3 px-3">RISK SCORE</th>
                  <th className="py-3 px-3">STATUS</th>
                  <th className="py-3 px-3">SOURCE IP</th>
                  <th className="py-3 px-3">TARGET ASSET</th>
                  <th className="py-3 px-3">ASSIGNEE</th>
                  <th className="py-3 px-3 text-right">ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {filteredIncidents.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className="border-b border-[#edf2f0] hover:bg-[#f0f5f3] transition-colors cursor-pointer group"
                  >
                    {/* Incident Title & ID */}
                    <td className="py-3.5 px-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono-code text-[11px] font-bold text-[#334d4a] bg-[#334d4a]/10 px-2 py-0.5 rounded">
                          {inc.id}
                        </span>
                        <span className="font-bold text-[#253835] group-hover:text-[#334d4a] transition-colors">
                          {inc.title}
                        </span>
                      </div>
                    </td>

                    {/* Severity Indicator */}
                    <td className="py-3.5 px-3">
                      <span
                        className={`text-[10px] font-extrabold px-2.5 py-1 rounded-full border uppercase inline-block ${getSeverityStyle(
                          inc.severity
                        )}`}
                      >
                        {inc.severity}
                      </span>
                    </td>

                    {/* Risk Score */}
                    <td className="py-3.5 px-3">
                      <span
                        className={`text-xs font-extrabold font-display px-2.5 py-0.5 rounded-md border inline-block ${getRiskScoreColor(
                          inc.risk_score || 70
                        )}`}
                      >
                        {inc.risk_score || 70}/100
                      </span>
                    </td>

                    {/* Status Pill */}
                    <td className="py-3.5 px-3">
                      <span
                        className={`text-[10px] font-extrabold px-2.5 py-1 rounded-full border uppercase inline-block ${getStatusStyle(
                          inc.status
                        )}`}
                      >
                        {inc.status}
                      </span>
                    </td>

                    {/* Source IP */}
                    <td className="py-3.5 px-3 font-mono-code font-semibold text-[#334d4a]">
                      {inc.source_ip}
                    </td>

                    {/* Target Asset */}
                    <td className="py-3.5 px-3 font-mono-code text-[#6c8582]">
                      {inc.target_asset}
                    </td>

                    {/* Assignee */}
                    <td className="py-3.5 px-3 text-[#253835] font-semibold">
                      <div className="flex items-center gap-1.5">
                        <User className="w-3.5 h-3.5 text-[#6c8582]" />
                        <span className="truncate max-w-[120px]">{inc.assigned_to || 'Unassigned'}</span>
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="py-3.5 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => {
                            updateIncidentStatus(inc.id, 'ACKNOWLEDGED');
                            onTriggerToast(`Incident ${inc.id} Acknowledged`);
                          }}
                          disabled={inc.status === 'ACKNOWLEDGED'}
                          className={`text-[11px] font-bold py-1 px-2.5 rounded-lg border-none cursor-pointer transition-all ${
                            inc.status === 'ACKNOWLEDGED'
                              ? 'bg-[#d49b28]/20 text-[#d49b28]'
                              : 'bg-[#d49b28] hover:bg-[#b8821a] text-white'
                          }`}
                        >
                          Acknowledge
                        </button>

                        <button
                          onClick={() => {
                            updateIncidentStatus(inc.id, 'RESOLVED');
                            onTriggerToast(`Incident ${inc.id} Resolved`);
                          }}
                          disabled={inc.status === 'RESOLVED'}
                          className={`text-[11px] font-bold py-1 px-2.5 rounded-lg border-none cursor-pointer transition-all ${
                            inc.status === 'RESOLVED'
                              ? 'bg-[#2d9d78]/20 text-[#2d9d78]'
                              : 'bg-[#2d9d78] hover:bg-[#237c5f] text-white'
                          }`}
                        >
                          Resolve
                        </button>

                        <button
                          onClick={() => setSelectedIncident(inc)}
                          className="p-1 rounded-lg bg-[#334d4a]/10 hover:bg-[#334d4a]/20 text-[#334d4a] border-none cursor-pointer"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Incident Detail Drawer */}
      {selectedIncident && (
        <IncidentDetailDrawer
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onUpdateStatus={(id, st) => {
            updateIncidentStatus(id, st);
            if (selectedIncident && selectedIncident.id === id) {
              setSelectedIncident((prev) => (prev ? { ...prev, status: st } : null));
            }
          }}
          onAssignAnalyst={(id, analyst) => {
            assignAnalyst(id, analyst);
            if (selectedIncident && selectedIncident.id === id) {
              setSelectedIncident((prev) => (prev ? { ...prev, assigned_to: analyst } : null));
            }
          }}
          onTriggerToast={onTriggerToast}
        />
      )}
    </div>
  );
};
