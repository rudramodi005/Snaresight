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
    crimson: 'bg-[#54162B] text-[#FDA481] border border-[#B4182D]',
    muted: 'bg-[#242E49] text-[#94A3B8] border border-[#37415C]',
    outline: 'bg-transparent text-[#FDA481] border border-[#37415C]',
    solid: 'bg-[#B4182D] text-white font-bold border border-[#B4182D]',
    // Threat Severities
    critical: 'bg-[#54162B] text-[#FDA481] font-bold border border-[#B4182D] shadow-[0_0_8px_rgba(180,24,45,0.4)]',
    high: 'bg-[#B4182D]/20 text-[#FDA481] font-bold border border-[#B4182D]/60',
    medium: 'bg-[#FDA481]/15 text-[#FDA481] border border-[#FDA481]/40',
    low: 'bg-[#242E49] text-[#94A3B8] border border-[#37415C]',
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
