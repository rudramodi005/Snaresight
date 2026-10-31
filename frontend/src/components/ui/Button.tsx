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
    // Solid Crimson with dark obsidian text for maximum contrast & crisp readability
    primary:
      'bg-[#FB3640] text-[#000F08] hover:bg-[#FB3640]/90 active:bg-[#FB3640]/80 shadow-[0_0_15px_rgba(251,54,64,0.35)] font-bold',
    // Transparent with Crimson border and Crimson text
    outline:
      'bg-transparent border border-[#FB3640]/40 text-[#FB3640] hover:border-[#FB3640] hover:bg-[#FB3640]/10',
    // Ghost with hover background
    ghost:
      'bg-transparent text-[#FB3640]/80 hover:text-[#FB3640] hover:bg-[#FB3640]/10',
    // Muted surface
    dim:
      'bg-[#FB3640]/10 border border-[#FB3640]/20 text-[#FB3640] hover:bg-[#FB3640]/20',
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

