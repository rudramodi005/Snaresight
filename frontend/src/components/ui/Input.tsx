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
          <label className="block text-xs font-mono uppercase tracking-wider text-[#FDA481]/90">
            {label}
          </label>
        )}
        <div className="relative flex items-center">
          {icon && (
            <span className="absolute left-3 text-[#94A3B8] pointer-events-none">
              {icon}
            </span>
          )}
          <input
            ref={ref}
            className={`w-full bg-[#181A2F] border border-[#37415C] rounded-lg px-3.5 py-2 text-xs font-mono text-[#FFFFFF] placeholder-[#94A3B8]/50 focus:outline-none focus:border-[#FDA481] focus:ring-1 focus:ring-[#FDA481]/30 transition-all ${
              icon ? 'pl-9' : ''
            } ${error ? 'border-[#B4182D] ring-1 ring-[#B4182D]/50' : ''} ${className}`}
            {...props}
          />
        </div>
        {error && (
          <p className="text-[10px] font-mono text-[#FDA481] mt-1">{error}</p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
export default Input;
