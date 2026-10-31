import React from 'react';

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'glow' | 'interactive' | 'flat';
  header?: React.ReactNode;
  footer?: React.ReactNode;
}

export const Card: React.FC<CardProps> = ({
  children,
  variant = 'default',
  header,
  footer,
  className = '',
  ...props
}) => {
  const variantClasses = {
    default:
      'bg-[#000F08] border border-[#FB3640]/15 shadow-sm',
    glow:
      'bg-[#000F08] border border-[#FB3640]/30 shadow-[0_0_20px_rgba(251,54,64,0.15)]',
    interactive:
      'bg-[#000F08] border border-[#FB3640]/15 hover:border-[#FB3640]/40 hover:bg-[#FB3640]/[0.02] transition-all cursor-pointer shadow-sm hover:shadow-[0_0_15px_rgba(251,54,64,0.2)]',
    flat:
      'bg-[#FB3640]/[0.03] border border-[#FB3640]/10',
  }[variant];

  return (
    <div
      className={`rounded-xl overflow-hidden text-[#FB3640] ${variantClasses} ${className}`}
      {...props}
    >
      {header && (
        <div className="px-5 py-3.5 border-b border-[#FB3640]/10 flex items-center justify-between bg-[#FB3640]/[0.02]">
          {header}
        </div>
      )}
      <div className="p-5">{children}</div>
      {footer && (
        <div className="px-5 py-3 border-t border-[#FB3640]/10 bg-[#FB3640]/[0.02]">
          {footer}
        </div>
      )}
    </div>
  );
};

export default Card;

