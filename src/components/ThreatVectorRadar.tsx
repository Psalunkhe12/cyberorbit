import React from 'react';
import { ThreatVector } from '../types';
import { Plane, ShieldAlert, CheckCircle2, Zap } from 'lucide-react';

interface ThreatVectorRadarProps {
  vector: ThreatVector;
  onIsolateVector: () => void;
}

export const ThreatVectorRadar: React.FC<ThreatVectorRadarProps> = ({
  vector,
  onIsolateVector,
}) => {
  return (
    <div className="bg-[#334d4a] text-white rounded-[32px] p-6 shadow-xl flex flex-col justify-between border border-white/10 h-full">
      <div>
        <div className="text-[10px] font-bold tracking-widest text-[#d49b28] uppercase flex items-center justify-between">
          <span>Threat Vector Radar</span>
          <span className="w-2 h-2 rounded-full bg-[#d49b28] animate-ping" />
        </div>

        <div className="flex justify-between items-center my-4">
          <div>
            <small className="opacity-60 text-[10px] font-bold uppercase tracking-wider block">
              ORIGIN
            </small>
            <h2 className="font-display text-2xl font-extrabold m-0 text-white tracking-tight">
              {vector.origin}
            </h2>
          </div>

          <span className="bg-white/12 px-3 py-1 rounded-full text-[11px] text-[#d49b28] font-bold tracking-wide uppercase border border-[#d49b28]/30">
            {vector.isIsolated ? 'ISOLATED & REROUTED' : vector.attackType}
          </span>

          <div className="text-right">
            <small className="opacity-60 text-[10px] font-bold uppercase tracking-wider block">
              TARGET
            </small>
            <h2 className="font-display text-2xl font-extrabold m-0 text-white tracking-tight">
              {vector.target}
            </h2>
          </div>
        </div>
      </div>

      {/* Radar Map Graphic */}
      <div className="h-[110px] w-full bg-[radial-gradient(circle_at_50%_50%,rgba(212,155,40,0.2)_0%,transparent_70%)] rounded-xl my-2 relative grid place-items-center border border-white/10 overflow-hidden">
        <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.03)_1px,transparent_1px)] bg-[size:16px_16px]" />
        
        <div className="flex items-center gap-4 text-[#d49b28] text-xl font-bold z-10 select-none">
          <Plane className={`w-6 h-6 ${vector.isIsolated ? 'text-gray-400' : 'text-[#d49b28] animate-pulse'}`} />
          <span className="tracking-widest text-[#d49b28] text-sm">
            {vector.isIsolated ? '─── ✖ ───' : '─── ✦ ───'}
          </span>
          <Plane className="w-6 h-6 rotate-90 text-[#d49b28]" />
        </div>

        {vector.isIsolated && (
          <div className="absolute inset-0 bg-[#334d4a]/85 backdrop-blur-xs flex items-center justify-center gap-2 text-xs font-bold text-[#2d9d78]">
            <CheckCircle2 className="w-4 h-4" />
            <span>Vector Traffic Quarantined at Edge Proxy</span>
          </div>
        )}
      </div>

      <div>
        <div className="flex justify-between text-xs my-1">
          <span className="text-white/70 font-semibold">Risk Level</span>
          <span className="text-[#d49b28] font-extrabold">{vector.riskLabel}</span>
        </div>

        <div className="h-2 bg-white/15 rounded-full overflow-hidden my-2">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              vector.isIsolated ? 'bg-[#2d9d78] w-1/12' : 'bg-[#d49b28]'
            }`}
            style={{ width: vector.isIsolated ? '8%' : `${vector.riskScore}%` }}
          />
        </div>

        <button
          id="isolateBtn"
          onClick={onIsolateVector}
          className={`w-full mt-2 py-2.5 px-4 rounded-full font-bold text-xs cursor-pointer transition-all border-none flex items-center justify-center gap-2 ${
            vector.isIsolated
              ? 'bg-[#2d9d78] text-white'
              : 'bg-[#d49b28] hover:bg-[#b8821a] text-white shadow-md'
          }`}
        >
          {vector.isIsolated ? (
            <>
              <CheckCircle2 className="w-4 h-4" />
              <span>Vector Isolated (Click to Re-enable)</span>
            </>
          ) : (
            <>
              <ShieldAlert className="w-4 h-4" />
              <span>Isolate Threat Vector</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
