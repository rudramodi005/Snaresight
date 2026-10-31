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
  const isCritical = norm === 'CRITICAL' || norm === 'OFFLINE' || norm === 'BREACH';

  return (
    <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#242E49] border border-[#37415C] text-xs font-mono text-[#E2E8F0]">
      <span
        className={`w-2 h-2 rounded-full shrink-0 ${
          isHealthy
            ? pulse ? 'bg-[#10B981] animate-pulse shadow-[0_0_8px_#10B981]' : 'bg-[#10B981]'
            : isCritical
            ? 'bg-[#B4182D] animate-pulse shadow-[0_0_8px_#B4182D]'
            : 'bg-[#FDA481] shadow-[0_0_6px_#FDA481]'
        }`}
      />
      <span className="text-[11px] font-semibold tracking-wider">
        {label || status}
      </span>
    </div>
  );
};

export default StatusIndicator;
