import React from 'react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'outline' | 'ghost' | 'dim';
  size?: 'sm' | 'md' | 'lg';
  icon?: React.ReactNode;
  isLoading?: boolean;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  icon,
  isLoading = false,
  className = '',
  disabled,
  ...props
}) => {
  const sizeClasses = {
    sm: 'px-2.5 py-1 text-xs',
    md: 'px-4 py-2 text-xs font-semibold',
    lg: 'px-6 py-3 text-sm font-bold',
  }[size];

  const variantClasses = {
    // Solid Crimson with white text and crimson shadow
    primary:
      'bg-[#B4182D] text-white hover:bg-[#B4182D]/90 active:bg-[#B4182D]/80 shadow-[0_0_15px_rgba(180,24,45,0.35)] font-bold',
    // Transparent with Muted Slate border and Peach Coral text
    outline:
      'bg-transparent border border-[#37415C] text-[#FDA481] hover:border-[#FDA481] hover:bg-[#FDA481]/10',
    // Ghost with hover background
    ghost:
      'bg-transparent text-[#CBD5E1] hover:text-[#FDA481] hover:bg-[#242E49]',
    // Muted surface with Slate border
    dim:
      'bg-[#242E49] border border-[#37415C] text-[#FDA481] hover:bg-[#37415C]/50',
  }[variant];

  return (
    <button
      disabled={disabled || isLoading}
      className={`inline-flex items-center justify-center gap-2 rounded-lg font-mono tracking-wide transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed select-none ${sizeClasses} ${variantClasses} ${className}`}
      {...props}
    >
      {isLoading ? (
        <span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin" />
      ) : icon ? (
        <span className="shrink-0">{icon}</span>
      ) : null}
      <span>{children}</span>
    </button>
  );
};

export default Button;
