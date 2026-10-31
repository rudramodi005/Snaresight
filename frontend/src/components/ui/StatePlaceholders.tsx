import React from 'react';

export const LoadingSkeleton: React.FC<{ rows?: number; className?: string }> = ({
  rows = 3,
  className = '',
}) => {
  return (
    <div className={`space-y-3 animate-pulse ${className}`}>
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="h-9 bg-[#FB3640]/5 rounded-lg border border-[#FB3640]/10"
          style={{ opacity: 1 - i * 0.15 }}
        />
      ))}
    </div>
  );
};

export const EmptyState: React.FC<{
  title: string;
  description?: string;
  action?: React.ReactNode;
  icon?: React.ReactNode;
}> = ({ title, description, action, icon }) => {
  return (
    <div className="py-16 px-4 text-center border border-dashed border-[#FB3640]/20 rounded-xl bg-[#000F08]">
      {icon ? (
        <div className="text-3xl mb-3 text-[#FB3640]/70 flex justify-center">{icon}</div>
      ) : (
        <div className="w-10 h-10 mx-auto mb-3 rounded-full border border-[#FB3640]/30 flex items-center justify-center text-[#FB3640]/50 font-mono">
          ∅
        </div>
      )}
      <h3 className="text-sm font-semibold text-[#FB3640] tracking-wide">{title}</h3>
      {description && (
        <p className="mt-1.5 text-xs text-[#FB3640]/60 max-w-sm mx-auto leading-relaxed font-mono">
          {description}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
};

