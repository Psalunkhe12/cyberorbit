import React, { useState, useEffect } from 'react';
import { Activity, Radio, Play, Pause, Server, Shield, ArrowDownUp } from 'lucide-react';

interface NetworkFlow {
  id: string;
  sourceIp: string;
  destPort: number;
  protocol: 'HTTPS' | 'gRPC' | 'DNS' | 'SSH' | 'UDP';
  bytes: string;
  packets: number;
  node: string;
  status: 'ESTABLISHED' | 'INSPECTING' | 'DROPPED' | 'RATE_LIMITED';
}

export const LiveTrafficView: React.FC = () => {
  const [isLive, setIsLive] = useState(true);
  const [flows, setFlows] = useState<NetworkFlow[]>([
    { id: 'fl-1', sourceIp: '185.220.101.42', destPort: 443, protocol: 'HTTPS', bytes: '14.2 MB', packets: 8420, node: 'edge-api-02', status: 'DROPPED' },
    { id: 'fl-2', sourceIp: '45.155.205.91', destPort: 80, protocol: 'HTTPS', bytes: '8.7 MB', packets: 5120, node: 'gateway-01', status: 'RATE_LIMITED' },
    { id: 'fl-3', sourceIp: '103.234.220.13', destPort: 8443, protocol: 'gRPC', bytes: '2.1 MB', packets: 1420, node: 'auth-service', status: 'INSPECTING' },
    { id: 'fl-4', sourceIp: '198.51.100.42', destPort: 53, protocol: 'DNS', bytes: '480 KB', packets: 340, node: 'dns-resolver-01', status: 'ESTABLISHED' },
    { id: 'fl-5', sourceIp: '104.28.201.88', destPort: 443, protocol: 'HTTPS', bytes: '45.1 MB', packets: 12400, node: 'partner-gateway', status: 'ESTABLISHED' },
    { id: 'fl-6', sourceIp: '91.199.118.17', destPort: 22, protocol: 'SSH', bytes: '120 KB', packets: 85, node: 'admin-portal', status: 'DROPPED' },
  ]);

  // Simulate real-time packet stream updates
  useEffect(() => {
    if (!isLive) return;
    const interval = setInterval(() => {
      setFlows((prev) => {
        const randomIp = `${Math.floor(Math.random() * 200 + 10)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254 + 1)}`;
        const protocols: NetworkFlow['protocol'][] = ['HTTPS', 'gRPC', 'DNS', 'SSH', 'UDP'];
        const nodes = ['edge-api-01', 'edge-api-02', 'gateway-01', 'auth-service'];
        const statuses: NetworkFlow['status'][] = ['ESTABLISHED', 'INSPECTING', 'DROPPED', 'RATE_LIMITED'];

        const newFlow: NetworkFlow = {
          id: `fl-${Date.now()}`,
          sourceIp: randomIp,
          destPort: [443, 80, 8443, 53, 22][Math.floor(Math.random() * 5)],
          protocol: protocols[Math.floor(Math.random() * protocols.length)],
          bytes: `${(Math.random() * 10).toFixed(1)} MB`,
          packets: Math.floor(Math.random() * 2000 + 100),
          node: nodes[Math.floor(Math.random() * nodes.length)],
          status: statuses[Math.floor(Math.random() * statuses.length)],
        };

        return [newFlow, ...prev.slice(0, 9)];
      });
    }, 2000);

    return () => clearInterval(interval);
  }, [isLive]);

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
            Monitoring active network sockets and TCP/UDP buffer states across edge gateways.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsLive(!isLive)}
            className={`px-5 py-2.5 rounded-full text-xs font-bold border-none cursor-pointer flex items-center gap-2 transition-all ${
              isLive
                ? 'bg-[#d49b28] hover:bg-[#b8821a] text-white shadow-md'
                : 'bg-[#334d4a] text-white'
            }`}
          >
            {isLive ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4 fill-current" />}
            <span>{isLive ? 'Pause Stream' : 'Resume Live Capture'}</span>
          </button>
        </div>
      </div>

      {/* Edge Node Status Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { name: 'edge-api-01', region: 'US-East (N. Virginia)', status: 'HEALTHY', load: '42%' },
          { name: 'edge-api-02', region: 'EU-Central (Frankfurt)', status: 'ELEVATED', load: '88%' },
          { name: 'gateway-01', region: 'AP-South (Mumbai)', status: 'HEALTHY', load: '58%' },
          { name: 'auth-service', region: 'US-West (Oregon)', status: 'HEALTHY', load: '31%' },
        ].map((node) => (
          <div
            key={node.name}
            className="bg-white rounded-2xl p-4 border border-[#d4deda] shadow-sm flex justify-between items-center"
          >
            <div>
              <span className="font-mono-code font-bold text-xs text-[#253835] block">
                {node.name}
              </span>
              <small className="text-[10px] text-[#6c8582] block">{node.region}</small>
            </div>
            <div className="text-right">
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded-full inline-block ${
                  node.status === 'ELEVATED'
                    ? 'bg-[#fdf3e1] text-[#b8821a]'
                    : 'bg-[#e8f5e9] text-[#2d9d78]'
                }`}
              >
                {node.status}
              </span>
              <small className="text-[10px] font-mono-code text-[#6c8582] block mt-1">
                CPU {node.load}
              </small>
            </div>
          </div>
        ))}
      </div>

      {/* Live Flow Stream Table */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
        <div className="flex justify-between items-center mb-4">
          <div className="font-display text-base font-extrabold text-[#253835]">
            Active Connection Sockets
          </div>
          <span className="text-xs text-[#6c8582] font-mono-code">
            Auto-refreshing (100ms sample buffer)
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#d4deda]">
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  SOURCE IP
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  PORT
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  PROTOCOL
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  BYTES TRANSFERRED
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  NODE
                </th>
                <th className="text-right py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  SOCKET STATUS
                </th>
              </tr>
            </thead>
            <tbody>
              {flows.map((flow) => (
                <tr key={flow.id} className="border-b border-[#edf2f0] hover:bg-[#f0f5f3]">
                  <td className="py-3 px-3 font-mono-code font-bold text-[#334d4a]">
                    {flow.sourceIp}
                  </td>
                  <td className="py-3 px-3 font-mono-code text-[#6c8582]">{flow.destPort}</td>
                  <td className="py-3 px-3 font-bold text-[#253835]">
                    <span className="bg-[#dce3e0] px-2 py-0.5 rounded text-[10px]">
                      {flow.protocol}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-mono-code text-[#253835]">
                    {flow.bytes} ({flow.packets} pkts)
                  </td>
                  <td className="py-3 px-3 font-mono-code text-[#6c8582]">{flow.node}</td>
                  <td className="py-3 px-3 text-right">
                    <span
                      className={`text-[10px] font-bold px-2.5 py-1 rounded-full uppercase ${
                        flow.status === 'DROPPED'
                          ? 'bg-[#fde8e8] text-[#d94b4b]'
                          : flow.status === 'RATE_LIMITED'
                          ? 'bg-[#fdf3e1] text-[#b8821a]'
                          : flow.status === 'INSPECTING'
                          ? 'bg-[#e3f2fd] text-[#1976d2]'
                          : 'bg-[#e8f5e9] text-[#2d9d78]'
                      }`}
                    >
                      {flow.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
