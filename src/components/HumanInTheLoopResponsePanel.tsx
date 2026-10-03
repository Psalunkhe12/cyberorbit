import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  CheckCircle,
  XCircle,
  UserCheck,
  Bot,
  Activity,
  AlertTriangle,
  Clock,
  Radio,
  Search,
  Lock,
} from 'lucide-react';

export interface ResponseActionRecordUI {
  id: string;
  requested_by: string;
  approved_by: string;
  action: 'block_ip' | 'investigate_host' | 'monitor_traffic' | 'isolate_host' | string;
  target: string;
  reason: string;
  timestamp: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | string;
  command_executed?: string | null;
}

interface HumanInTheLoopResponsePanelProps {
  onTriggerToast: (msg: string) => void;
  currentOperatorName?: string;
}

export const HumanInTheLoopResponsePanel: React.FC<HumanInTheLoopResponsePanelProps> = ({
  onTriggerToast,
  currentOperatorName = 'Sarah Chen (SOC Lead)',
}) => {
  const [actions, setActions] = useState<ResponseActionRecordUI[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchActions = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/response-actions');
      if (res.ok) {
        const data = await res.json();
        setActions(data);
      }
    } catch (err) {
      console.error('Failed to fetch response actions:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchActions();
  }, []);

  const handleDecide = async (actionId: string, decision: 'APPROVED' | 'REJECTED') => {
    try {
      const res = await fetch('/api/response-actions/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action_id: actionId,
          decision,
          approved_by: currentOperatorName,
        }),
      });

      if (res.ok) {
        const updatedRecord: ResponseActionRecordUI = await res.json();
        setActions((prev) =>
          prev.map((a) => (a.id === actionId ? updatedRecord : a))
        );
        onTriggerToast(
          `Action ${updatedRecord.action} on ${updatedRecord.target} was ${decision} by ${currentOperatorName}`
        );
      }
    } catch (err) {
      console.error('Failed to record decision:', err);
      // Local optimistic update
      setActions((prev) =>
        prev.map((a) =>
          a.id === actionId
            ? {
                ...a,
                status: decision,
                approved_by: currentOperatorName,
                timestamp: new Date().toISOString(),
              }
            : a
        )
      );
      onTriggerToast(`Action ${decision} for ${actionId}`);
    }
  };

  const getActionBadge = (actionStr: string) => {
    switch (actionStr.toLowerCase()) {
      case 'block_ip':
        return {
          label: 'BLOCK IP',
          icon: <Lock className="w-3.5 h-3.5" />,
          color: 'bg-[#fde8e8] text-[#d94b4b] border-[#f8b4b4]',
        };
      case 'unblock_ip':
        return {
          label: 'UNBLOCK IP',
          icon: <CheckCircle className="w-3.5 h-3.5" />,
          color: 'bg-[#e8f5e9] text-[#2d9d78] border-[#a5d6a7]',
        };
      case 'isolate_host':
        return {
          label: 'ISOLATE HOST',
          icon: <ShieldAlert className="w-3.5 h-3.5" />,
          color: 'bg-[#fdf3e1] text-[#b8821a] border-[#f6d79b]',
        };
      case 'monitor_host':
      case 'monitor_traffic':
      case 'investigate_host':
      default:
        return {
          label: 'MONITOR HOST',
          icon: <Radio className="w-3.5 h-3.5" />,
          color: 'bg-[#e3f2fd] text-[#1976d2] border-[#90caf9]',
        };
    }
  };

  const pendingActions = actions.filter((a) => a.status === 'PENDING');
  const historyActions = actions.filter((a) => a.status !== 'PENDING');

  return (
    <div className="flex flex-col gap-6">
      {/* Header Banner */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm flex flex-wrap justify-between items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <UserCheck className="w-5 h-5 text-[#d49b28]" />
            <h2 className="font-display text-lg font-extrabold text-[#253835] m-0">
              Human-in-the-Loop Incident Response Control
            </h2>
          </div>
          <p className="text-xs text-[#6c8582] mt-1 m-0">
            Strict AI Safety Policy Enforced: AI recommends actions; Human Analyst explicitly approves or rejects before execution.
          </p>
        </div>

        <div className="flex items-center gap-2 bg-[#f0f5f3] px-3.5 py-1.5 rounded-full border border-[#d4deda]">
          <Bot className="w-4 h-4 text-[#334d4a]" />
          <span className="text-xs font-bold text-[#253835]">AI Direct Execution: </span>
          <span className="text-[11px] font-extrabold text-[#d94b4b] bg-[#fde8e8] px-2 py-0.5 rounded-full uppercase border border-[#f8b4b4]">
            PROHIBITED
          </span>
        </div>
      </div>

      {/* Pending Approval Queue */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
        <div className="flex justify-between items-center mb-4">
          <h3 className="font-display text-base font-extrabold text-[#253835] m-0 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-[#d49b28]" />
            <span>Pending Analyst Approval Queue</span>
            <span className="text-xs font-bold bg-[#334d4a] text-white px-2.5 py-0.5 rounded-full ml-1">
              {pendingActions.length}
            </span>
          </h3>
          <span className="text-[11px] font-bold text-[#6c8582]">
            Current Operator: <span className="text-[#334d4a] font-extrabold">{currentOperatorName}</span>
          </span>
        </div>

        {pendingActions.length === 0 ? (
          <div className="text-center py-8 bg-[#f8faf9] rounded-2xl border border-dashed border-[#c2d1cc]">
            <CheckCircle className="w-8 h-8 text-[#2d9d78] mx-auto mb-2 opacity-80" />
            <p className="text-xs font-bold text-[#253835] m-0">No Pending AI Response Recommendations</p>
            <p className="text-[11px] text-[#6c8582] mt-1">All AI containment advisories have been reviewed.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {pendingActions.map((rec) => {
              const badge = getActionBadge(rec.action);
              return (
                <div
                  key={rec.id}
                  className="bg-[#f8faf9] p-4 rounded-2xl border border-[#d4deda] flex flex-wrap justify-between items-center gap-4 hover:border-[#334d4a]/30 transition-all"
                >
                  <div className="space-y-1.5 max-w-xl">
                    <div className="flex items-center gap-2.5">
                      <span className={`text-[10px] font-extrabold px-2.5 py-0.5 rounded-full border uppercase flex items-center gap-1 ${badge.color}`}>
                        {badge.icon}
                        {badge.label}
                      </span>
                      <span className="font-mono-code font-bold text-xs text-[#253835]">
                        Target: <span className="text-[#d49b28]">{rec.target}</span>
                      </span>
                      <span className="text-[10px] font-bold bg-[#334d4a]/10 text-[#334d4a] px-2 py-0.5 rounded-full flex items-center gap-1">
                        <Bot className="w-3 h-3" />
                        {rec.requested_by}
                      </span>
                    </div>

                    <p className="text-xs text-[#334d4a] font-medium m-0">
                      <span className="font-bold text-[#253835]">Reason: </span>
                      {rec.reason}
                    </p>

                    <div className="text-[10px] text-[#6c8582] flex items-center gap-3">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        Requested: {new Date(rec.timestamp).toLocaleTimeString()}
                      </span>
                      <span>•</span>
                      <span>
                        Status: <b className="text-[#b8821a] uppercase">PENDING APPROVAL</b>
                      </span>
                    </div>
                  </div>

                  {/* Approve / Reject Decision Buttons */}
                  <div className="flex items-center gap-2.5">
                    <button
                      onClick={() => handleDecide(rec.id, 'APPROVED')}
                      className="bg-[#2d9d78] hover:bg-[#238062] text-white px-5 py-2.5 rounded-full font-extrabold text-xs border-none cursor-pointer flex items-center gap-1.5 shadow-xs hover:shadow transition-all"
                    >
                      <CheckCircle className="w-4 h-4" />
                      <span>Approve</span>
                    </button>
                    <button
                      onClick={() => handleDecide(rec.id, 'REJECTED')}
                      className="bg-[#f0f5f3] hover:bg-[#e3eae7] text-[#d94b4b] border border-[#d4deda] hover:border-[#f8b4b4] px-4 py-2.5 rounded-full font-bold text-xs cursor-pointer flex items-center gap-1.5 transition-all"
                    >
                      <XCircle className="w-4 h-4 text-[#d94b4b]" />
                      <span>Reject</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Decision Audit Log Table */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
        <h3 className="font-display text-base font-extrabold text-[#253835] m-0 mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-[#334d4a]" />
          <span>Response Decisions Audit Log (`response_actions`)</span>
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#d4deda]">
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">ACTION & TARGET</th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">REQUESTED BY</th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">APPROVED BY</th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">TIMESTAMP</th>
                <th className="text-right py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">STATUS</th>
              </tr>
            </thead>
            <tbody>
              {actions.map((rec) => {
                const badge = getActionBadge(rec.action);
                return (
                  <tr key={rec.id} className="border-b border-[#edf2f0] hover:bg-[#f0f5f3]">
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-extrabold px-2 py-0.5 rounded-full border uppercase ${badge.color}`}>
                          {badge.label}
                        </span>
                        <span className="font-mono-code font-bold text-[#253835]">{rec.target}</span>
                      </div>
                    </td>
                    <td className="py-3 px-3 font-semibold text-[#334d4a]">{rec.requested_by}</td>
                    <td className="py-3 px-3 font-semibold text-[#253835]">{rec.approved_by}</td>
                    <td className="py-3 px-3 font-mono-code text-[11px] text-[#6c8582]">
                      {new Date(rec.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <span
                        className={`text-[10px] font-extrabold px-2.5 py-1 rounded-full uppercase inline-block border ${
                          rec.status === 'APPROVED' || rec.status === 'EXECUTED'
                            ? 'bg-[#e8f5e9] text-[#2d9d78] border-[#a5d6a7]'
                            : rec.status === 'REJECTED'
                            ? 'bg-[#fde8e8] text-[#d94b4b] border-[#f8b4b4]'
                            : 'bg-[#fdf3e1] text-[#b8821a] border-[#f6d79b]'
                        }`}
                      >
                        {rec.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
