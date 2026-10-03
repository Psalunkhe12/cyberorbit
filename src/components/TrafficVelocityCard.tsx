import React, { useState } from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';
import { TrafficPoint } from '../types';
import { RefreshCw, Zap, Flame } from 'lucide-react';

interface TrafficVelocityCardProps {
  data: TrafficPoint[];
  onToggleLive: () => void;
  isLive: boolean;
}

export const TrafficVelocityCard: React.FC<TrafficVelocityCardProps> = ({
  data,
  onToggleLive,
  isLive,
}) => {
  const [metricKey, setMetricKey] = useState<'throughputGbps' | 'activeFlows' | 'threatRequests'>('throughputGbps');

  return (
    <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm flex flex-col justify-between h-full">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h2 className="font-display text-lg font-extrabold text-[#253835] tracking-tight m-0">
            Traffic Velocity
          </h2>
          <p className="text-xs text-[#6c8582] mt-0.5 m-0">
            Inbound request volume per second · Last 60 Minutes
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Metric Selector Tabs */}
          <div className="bg-[#dce3e0] p-1 rounded-full flex gap-1 text-[11px] font-bold">
            <button
              onClick={() => setMetricKey('throughputGbps')}
              className={`px-3 py-1 rounded-full border-none cursor-pointer transition-all ${
                metricKey === 'throughputGbps'
                  ? 'bg-white text-[#253835] shadow-xs'
                  : 'text-[#6c8582] hover:text-[#253835]'
              }`}
            >
              Gbps
            </button>
            <button
              onClick={() => setMetricKey('activeFlows')}
              className={`px-3 py-1 rounded-full border-none cursor-pointer transition-all ${
                metricKey === 'activeFlows'
                  ? 'bg-white text-[#253835] shadow-xs'
                  : 'text-[#6c8582] hover:text-[#253835]'
              }`}
            >
              Flows
            </button>
            <button
              onClick={() => setMetricKey('threatRequests')}
              className={`px-3 py-1 rounded-full border-none cursor-pointer transition-all ${
                metricKey === 'threatRequests'
                  ? 'bg-[#d94b4b] text-white shadow-xs'
                  : 'text-[#6c8582] hover:text-[#253835]'
              }`}
            >
              Threats
            </button>
          </div>

          <button
            onClick={onToggleLive}
            title={isLive ? 'Pause Live Stream' : 'Resume Live Stream'}
            className={`px-3 py-1.5 rounded-full text-[11px] font-bold border-none cursor-pointer flex items-center gap-1.5 transition-all ${
              isLive ? 'bg-[#dce3e0] text-[#253835]' : 'bg-[#d49b28] text-white'
            }`}
          >
            <RefreshCw className={`w-3 h-3 ${isLive ? 'animate-spin' : ''}`} />
            <span>{isLive ? 'REAL-TIME' : 'PAUSED'}</span>
          </button>
        </div>
      </div>

      <div className="h-[220px] w-full mt-2">
        {data.length === 0 ? (
          <div className="h-full w-full flex flex-col items-center justify-center bg-[#f8faf9] rounded-2xl border border-dashed border-[#c2d1cc] p-6 text-center">
            <Zap className="w-8 h-8 text-[#9cb1ae] mb-2 opacity-60" />
            <p className="text-xs font-bold text-[#334d4a] m-0">No Traffic Telemetry Metrics</p>
            <p className="text-[11px] text-[#6c8582] mt-1 m-0">
              No traffic telemetry points recorded in database. Waiting for ingress network traffic.
            </p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="goldGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#d49b28" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#d49b28" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#d94b4b" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#d94b4b" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="#9cb1ae" fontSize={10} tickLine={false} axisLine={false} />
              <YAxis stroke="#9cb1ae" fontSize={10} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#334d4a',
                  borderColor: '#d49b28',
                  borderRadius: '12px',
                  color: '#ffffff',
                  fontSize: '12px',
                  fontWeight: '600',
                }}
                labelStyle={{ color: '#d49b28' }}
              />
              <Area
                type="monotone"
                dataKey={metricKey}
                stroke={metricKey === 'threatRequests' ? '#d94b4b' : '#d49b28'}
                strokeWidth={3}
                fillOpacity={1}
                fill={`url(#${metricKey === 'threatRequests' ? 'redGrad' : 'goldGrad'})`}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};
