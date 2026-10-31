import React from 'react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, icon, className = '', ...props }, ref) => {
    return (
      <div className="w-full space-y-1">
        {label && (
          <label className="block text-xs font-mono uppercase tracking-wider text-[#FB3640]/70">
            {label}
          </label>
        )}
        <div className="relative flex items-center">
          {icon && (
            <span className="absolute left-3 text-[#FB3640]/50 pointer-events-none">
              {icon}
            </span>
          )}
          <input
            ref={ref}
            className={`w-full bg-[#000F08] border border-[#FB3640]/20 rounded-lg px-3.5 py-2 text-xs font-mono text-[#FB3640] placeholder-[#FB3640]/30 focus:outline-none focus:border-[#FB3640] focus:ring-1 focus:ring-[#FB3640]/30 transition-all ${
              icon ? 'pl-9' : ''
            } ${error ? 'border-[#FB3640] ring-1 ring-[#FB3640]/50' : ''} ${className}`}
            {...props}
          />
        </div>
        {error && (
          <p className="text-[10px] font-mono text-[#FB3640] mt-1">{error}</p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
export default Input;

