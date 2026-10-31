import React from 'react';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'crimson' | 'muted' | 'outline' | 'solid' | 'critical' | 'high' | 'medium' | 'low';
  size?: 'sm' | 'md';
  dot?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'crimson',
  size = 'md',
  dot = false,
  className = '',
  ...props
}) => {
  const sizeClasses = {
    sm: 'px-1.5 py-0.5 text-[9px]',
    md: 'px-2 py-0.5 text-[10px]',
  }[size];

  const variantClasses = {
    crimson: 'bg-[#FB3640]/15 text-[#FB3640] border border-[#FB3640]/30',
    muted: 'bg-[#FB3640]/5 text-[#FB3640]/60 border border-[#FB3640]/10',
    outline: 'bg-transparent text-[#FB3640] border border-[#FB3640]/40',
    solid: 'bg-[#FB3640] text-[#000F08] font-bold border border-[#FB3640]',
    // Threat Severities (strictly using #FB3640 with distinct opacities and visual weights)
    critical: 'bg-[#FB3640] text-[#000F08] font-bold border border-[#FB3640] shadow-[0_0_8px_rgba(251,54,64,0.4)]',
    high: 'bg-[#FB3640]/25 text-[#FB3640] font-bold border border-[#FB3640]/50',
    medium: 'bg-[#FB3640]/15 text-[#FB3640]/90 border border-[#FB3640]/30',
    low: 'bg-[#FB3640]/5 text-[#FB3640]/65 border border-[#FB3640]/15',
  }[variant];

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono uppercase tracking-wider rounded ${sizeClasses} ${variantClasses} ${className}`}
      {...props}
    >
      {dot && <span className="w-1.5 h-1.5 rounded-full bg-current shrink-0 animate-pulse" />}
      <span>{children}</span>
    </span>
  );
};

export default Badge;

