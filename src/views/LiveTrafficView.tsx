import React from 'react';
import { Activity, Radio, Play, Pause, Server, Shield, ArrowDownUp, ShieldCheck } from 'lucide-react';
import { useRealtimeNetworkEvents } from '../hooks/useRealtimeNetworkEvents';

export const LiveTrafficView: React.FC = () => {
  const { networkEvents, loading, isLive, reload } = useRealtimeNetworkEvents();

  return (
    <div className="flex flex-col gap-5">
      {/* Top Banner Control */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm flex flex-wrap justify-between items-center gap-4">
        <div>
          <h2 className="font-display text-lg font-extrabold text-[#253835] flex items-center gap-2 m-0">
            <Activity className="w-5 h-5 text-[#d49b28]" />
            <span>Deep Packet Stream Inspector</span>
          </h2>
          <p className="text-xs text-[#6c8582] mt-1 m-0">
            Monitoring active network sockets and TCP/UDP buffer states from database network_events.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span
            className={`text-xs font-bold px-3 py-1 rounded-full flex items-center gap-1.5 ${
              isLive ? 'bg-[#e8f5e9] text-[#2d9d78]' : 'bg-[#fdf3e1] text-[#b8821a]'
            }`}
          >
            <Radio className="w-3.5 h-3.5 animate-pulse" />
            <span>{isLive ? 'REALTIME DB SUBSCRIBED' : 'POLLING / STATIC'}</span>
          </span>

          <button
            onClick={reload}
            className="bg-[#334d4a] hover:bg-[#253835] text-white px-5 py-2.5 rounded-full text-xs font-bold border-none cursor-pointer transition-all"
          >
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Live Flow Stream Table */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
        <div className="flex justify-between items-center mb-4">
          <div className="font-display text-base font-extrabold text-[#253835]">
            Active Connection Sockets ({networkEvents.length})
          </div>
          <span className="text-xs text-[#6c8582] font-mono-code">
            Directly queried from public.network_events
          </span>
        </div>

        <div className="overflow-x-auto">
          {loading && networkEvents.length === 0 ? (
            <div className="py-12 text-center text-xs font-bold text-[#6c8582]">
              Loading network events from database...
            </div>
          ) : networkEvents.length === 0 ? (
            <div className="py-12 px-4 text-center bg-[#f8faf9] rounded-2xl border border-dashed border-[#c2d1cc]">
              <ShieldCheck className="w-8 h-8 text-[#2d9d78] mx-auto mb-2 opacity-70" />
              <p className="text-xs font-bold text-[#334d4a] m-0">No Network Events Recorded</p>
              <p className="text-[11px] text-[#6c8582] mt-1 m-0">
                The network_events database table is currently empty. Run Zeek/Suricata collectors or ingest packets to stream events.
              </p>
            </div>
          ) : (
            <table className="w-full border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#d4deda]">
                  <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    TIMESTAMP
                  </th>
                  <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    SOURCE IP
                  </th>
                  <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    DESTINATION IP / PORT
                  </th>
                  <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    PROTOCOL
                  </th>
                  <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    EVENT TYPE / APPLICATION
                  </th>
                  <th className="text-right py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    TRAFFIC VOLUME
                  </th>
                </tr>
              </thead>
              <tbody>
                {networkEvents.map((ev) => (
                  <tr key={ev.id} className="border-b border-[#edf2f0] hover:bg-[#f0f5f3]">
                    <td className="py-3 px-3 font-mono-code text-[11px] text-[#6c8582]">
                      {new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-3 px-3 font-mono-code font-bold text-[#334d4a]">
                      {ev.source_ip || 'N/A'}
                    </td>
                    <td className="py-3 px-3 font-mono-code text-[#253835]">
                      {ev.destination_ip || 'N/A'} {ev.destination_port ? `:${ev.destination_port}` : ''}
                    </td>
                    <td className="py-3 px-3 font-bold text-[#253835]">
                      <span className="bg-[#dce3e0] px-2 py-0.5 rounded text-[10px]">
                        {ev.protocol || 'TCP'}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-semibold text-[#253835]">
                      {ev.event_type || ev.application || 'connection'}
                    </td>
                    <td className="py-3 px-3 text-right font-mono-code text-[#253835]">
                      {((ev.bytes_in + ev.bytes_out) / 1024).toFixed(1)} KB ({(ev.packets_in + ev.packets_out)} pkts)
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};
