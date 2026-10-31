import React from 'react';

export interface StatusIndicatorProps {
  status: 'ONLINE' | 'ACTIVE' | 'DEGRADED' | 'OFFLINE' | 'CRITICAL' | 'HEALTHY' | string;
  label?: string;
  pulse?: boolean;
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({
  status,
  label,
  pulse = true,
}) => {
  const norm = status.toUpperCase();
  const isHealthy = norm === 'ONLINE' || norm === 'ACTIVE' || norm === 'HEALTHY' || norm === 'CONNECTED';

  return (
    <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#000F08] border border-[#FB3640]/25 text-xs font-mono text-[#FB3640]">
      <span
        className={`w-2 h-2 rounded-full bg-[#FB3640] shrink-0 ${
          isHealthy && pulse ? 'animate-pulse shadow-[0_0_8px_#FB3640]' : 'opacity-60'
        }`}
      />
      <span className="text-[11px] font-semibold tracking-wider">
        {label || status}
      </span>
    </div>
  );
};

export default StatusIndicator;

