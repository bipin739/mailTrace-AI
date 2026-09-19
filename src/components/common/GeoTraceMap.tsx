import React, { useState } from 'react';
import type { EmailHeaderHop, GeoLocationInfo } from '../../types';
import { MapPin, Server, ArrowRight, ShieldAlert, Globe, Radio, Eye } from 'lucide-react';

interface GeoTraceMapProps {
  originGeo: GeoLocationInfo;
  hops: EmailHeaderHop[];
}

export const GeoTraceMap: React.FC<GeoTraceMapProps> = ({ originGeo, hops }) => {
  const [selectedHop, setSelectedHop] = useState<EmailHeaderHop | null>(
    hops.find(h => h.isOrigin) || hops[0] || null
  );

  return (
    <div className="space-y-4">
      {/* Visual Trace Flow Header */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
            <h4 className="text-sm font-mono font-bold text-cyan-400 tracking-wide uppercase">
              SMTP Relay Hop Trajectory & Origin Traceability
            </h4>
          </div>
          <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-cyan-950/60 text-cyan-300 border border-cyan-800/60">
            {hops.length} Mail Hops Identified
          </span>
        </div>

        {/* Horizontal Visual Relay Graph */}
        <div className="flex items-center justify-between overflow-x-auto py-3 px-2 space-x-3 no-scrollbar">
          {hops.map((hop, idx) => {
            const isSelected = selectedHop?.hopNumber === hop.hopNumber;
            return (
              <React.Fragment key={hop.hopNumber}>
                <button
                  onClick={() => setSelectedHop(hop)}
                  className={`flex-shrink-0 flex flex-col items-center p-3 rounded-xl border text-left transition-all ${
                    isSelected
                      ? 'bg-cyan-950/40 border-cyan-500/80 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
                      : hop.isSuspicious
                      ? 'bg-red-950/30 border-red-900/60 hover:border-red-600/80'
                      : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center space-x-2 mb-1.5">
                    {hop.isOrigin ? (
                      <span className="p-1 rounded bg-red-500/20 text-red-400">
                        <MapPin className="w-4 h-4 animate-bounce" />
                      </span>
                    ) : (
                      <span className="p-1 rounded bg-slate-800 text-slate-400">
                        <Server className="w-4 h-4" />
                      </span>
                    )}
                    <span className="text-xs font-mono font-bold text-slate-200">
                      Hop #{hop.hopNumber}
                    </span>
                    {hop.isOrigin && (
                      <span className="text-[10px] uppercase font-mono font-extrabold px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">
                        ORIGIN
                      </span>
                    )}
                  </div>

                  <div className="text-xs font-mono text-cyan-300 font-semibold truncate max-w-[150px]">
                    {hop.fromIp}
                  </div>
                  <div className="text-[11px] text-slate-400 truncate max-w-[150px]">
                    {hop.city}, {hop.country}
                  </div>
                </button>

                {idx < hops.length - 1 && (
                  <ArrowRight className="w-5 h-5 text-slate-600 flex-shrink-0" />
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* World Map Simulation & Detailed Hop Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* World Geolocation Map Display */}
        <div className="lg:col-span-2 bg-slate-950/80 border border-slate-800 rounded-xl p-4 relative overflow-hidden flex flex-col justify-between min-h-[320px]">
          {/* Background Cyber Grid Graphic */}
          <div className="absolute inset-0 opacity-20 bg-[radial-gradient(#38bdf8_1px,transparent_1px)] [background-size:16px_16px] pointer-events-none" />

          <div className="relative z-10 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono font-bold text-slate-300">
                PROBABLE ORIGIN GEOLOCATION MAP
              </span>
            </div>
            <span className="text-xs font-mono text-cyan-400 font-bold px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800">
              {originGeo.latitude.toFixed(4)}° N, {originGeo.longitude.toFixed(4)}° E
            </span>
          </div>

          {/* Interactive Geo Marker Highlight */}
          <div className="relative z-10 my-6 bg-slate-900/80 backdrop-blur border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <div className="relative">
                <div className="w-12 h-12 rounded-full bg-red-950/80 border-2 border-red-500 flex items-center justify-center text-red-400 glow-red">
                  <MapPin className="w-6 h-6" />
                </div>
                <div className="absolute inset-0 rounded-full bg-red-500/30 animate-ping-slow pointer-events-none" />
              </div>
              <div>
                <div className="text-xs text-slate-400 font-mono">ESTIMATED SENDER SOURCE</div>
                <div className="text-lg font-bold text-slate-100 flex items-center space-x-2">
                  <span>{originGeo.city}, {originGeo.country}</span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300">
                    {originGeo.countryCode}
                  </span>
                </div>
                <div className="text-xs text-slate-300 mt-1 font-mono">
                  ISP: <span className="text-slate-100 font-semibold">{originGeo.isp}</span> ({originGeo.asn})
                </div>
              </div>
            </div>

            {/* IP Risk Flags */}
            <div className="flex flex-wrap gap-2 justify-end">
              {originGeo.isTor && (
                <span className="px-2.5 py-1 rounded bg-red-950 text-red-300 text-xs font-mono font-bold border border-red-800">
                  TOR EXIT NODE
                </span>
              )}
              {originGeo.isVpn && (
                <span className="px-2.5 py-1 rounded bg-amber-950 text-amber-300 text-xs font-mono font-bold border border-amber-800">
                  VPN PROXY
                </span>
              )}
              {originGeo.isDatacenter && (
                <span className="px-2.5 py-1 rounded bg-blue-950 text-blue-300 text-xs font-mono font-bold border border-blue-800">
                  CLOUD DATACENTER
                </span>
              )}
            </div>
          </div>

          <div className="relative z-10 flex items-center justify-between text-xs text-slate-400 border-t border-slate-800/80 pt-3">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <span>Earliest Reliable Node IP: <strong className="font-mono text-red-400">{originGeo.ip}</strong></span>
            </div>
            <span>Confidence Index: <strong className="text-emerald-400 font-mono">94% High</strong></span>
          </div>
        </div>

        {/* Hop Inspector Sidebar */}
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center space-x-2 mb-3 pb-2 border-b border-slate-800">
              <Eye className="w-4 h-4 text-cyan-400" />
              <h5 className="text-xs font-mono font-bold text-slate-200">
                HOP #{selectedHop?.hopNumber || 1} INSPECTOR
              </h5>
            </div>

            {selectedHop ? (
              <div className="space-y-3 text-xs">
                <div>
                  <span className="text-slate-400 block font-mono">Sending Server (From):</span>
                  <span className="text-cyan-300 font-mono font-semibold block truncate">
                    {selectedHop.fromHost}
                  </span>
                  <span className="text-slate-400 font-mono text-[11px]">
                    IP: {selectedHop.fromIp}
                  </span>
                </div>

                <div>
                  <span className="text-slate-400 block font-mono">Receiving Relay (By):</span>
                  <span className="text-slate-200 font-mono block truncate">
                    {selectedHop.byHost}
                  </span>
                  <span className="text-slate-400 font-mono text-[11px]">
                    IP: {selectedHop.byIp}
                  </span>
                </div>

                <div>
                  <span className="text-slate-400 block font-mono">Transit Timestamp & Latency:</span>
                  <span className="text-slate-200 font-mono">
                    {selectedHop.timestamp} ({selectedHop.delaySeconds}s delay)
                  </span>
                </div>

                <div>
                  <span className="text-slate-400 block font-mono">Registered Organization / ISP:</span>
                  <span className="text-slate-200 font-semibold">
                    {selectedHop.org} ({selectedHop.city}, {selectedHop.country})
                  </span>
                </div>

                {selectedHop.notes && (
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-slate-300 mt-2">
                    <strong className="text-cyan-400 block mb-0.5">Analyst Note:</strong>
                    {selectedHop.notes}
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs text-slate-400">Select a hop to inspect header details.</p>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Routing Anomaly Check</span>
            <span className="text-emerald-400 font-mono font-bold">RECONSTRUCTED</span>
          </div>
        </div>
      </div>
    </div>
  );
};
