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
      'bg-[#242E49] border border-[#37415C] shadow-sm',
    glow:
      'bg-[#242E49] border border-[#FDA481]/40 shadow-[0_0_20px_rgba(253,164,129,0.15)]',
    interactive:
      'bg-[#242E49] border border-[#37415C] hover:border-[#FDA481]/50 hover:bg-[#2d3a5a] transition-all cursor-pointer shadow-sm hover:shadow-[0_0_15px_rgba(253,164,129,0.15)]',
    flat:
      'bg-[#181A2F] border border-[#37415C]',
  }[variant];

  return (
    <div
      className={`rounded-xl overflow-hidden text-[#E2E8F0] ${variantClasses} ${className}`}
      {...props}
    >
      {header && (
        <div className="px-5 py-3.5 border-b border-[#37415C] flex items-center justify-between bg-[#181A2F]/40">
          {header}
        </div>
      )}
      <div className="p-5">{children}</div>
      {footer && (
        <div className="px-5 py-3 border-t border-[#37415C] bg-[#181A2F]/40">
          {footer}
        </div>
      )}
    </div>
  );
};

export default Card;
