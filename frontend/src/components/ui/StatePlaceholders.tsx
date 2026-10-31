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
          className="h-9 bg-[#242E49] rounded-lg border border-[#37415C]"
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
    <div className="py-16 px-4 text-center border border-dashed border-[#37415C] rounded-xl bg-[#242E49]/50">
      {icon ? (
        <div className="text-3xl mb-3 text-[#FDA481] flex justify-center">{icon}</div>
      ) : (
        <div className="w-10 h-10 mx-auto mb-3 rounded-full border border-[#37415C] flex items-center justify-center text-[#94A3B8] font-mono">
          ∅
        </div>
      )}
      <h3 className="text-sm font-semibold text-[#FDA481] tracking-wide">{title}</h3>
      {description && (
        <p className="mt-1.5 text-xs text-[#94A3B8] max-w-sm mx-auto leading-relaxed font-mono">
          {description}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
};
