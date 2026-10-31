import React from 'react';

export interface BrandLogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl' | number;
  showWordmark?: boolean;
  className?: string;
}

export const BrandLogo: React.FC<BrandLogoProps> = ({
  size = 'md',
  showWordmark = true,
  className = '',
}) => {
  const pixelSizes = typeof size === 'number' ? size : {
    sm: 24,
    md: 32,
    lg: 44,
    xl: 60,
  }[size];

  return (
    <div className={`inline-flex items-center gap-3 select-none ${className}`}>
      {/* Precision Geometric Deception Node Mark in #FB3640 */}
      <svg
        width={pixelSizes}
        height={pixelSizes}
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="shrink-0"
      >
        {/* Outer Hexagonal Radar Shell */}
        <polygon
          points="50,6 90,28 90,72 50,94 10,72 10,28"
          stroke="#FB3640"
          strokeWidth="4"
          fill="#000F08"
        />
        {/* Concentric Snare Mesh Grid */}
        <polygon
          points="50,22 76,36 76,64 50,78 24,64 24,36"
          stroke="#FB3640"
          strokeWidth="2"
          strokeOpacity="0.45"
          fill="none"
        />
        {/* Coordinate Intersections */}
        <line x1="50" y1="6" x2="50" y2="94" stroke="#FB3640" strokeWidth="1.5" strokeOpacity="0.3" strokeDasharray="3 3" />
        <line x1="10" y1="50" x2="90" y2="50" stroke="#FB3640" strokeWidth="1.5" strokeOpacity="0.3" strokeDasharray="3 3" />
        {/* Core Deception Focal Singularity */}
        <circle cx="50" cy="50" r="10" fill="#FB3640" />
        <circle cx="50" cy="50" r="16" stroke="#FB3640" strokeWidth="2" strokeOpacity="0.75" />
        {/* Satellite Honeypot Nodes */}
        <circle cx="50" cy="22" r="3.5" fill="#FB3640" />
        <circle cx="76" cy="36" r="3.5" fill="#FB3640" />
        <circle cx="76" cy="64" r="3.5" fill="#FB3640" />
        <circle cx="50" cy="78" r="3.5" fill="#FB3640" />
        <circle cx="24" cy="64" r="3.5" fill="#FB3640" />
        <circle cx="24" cy="36" r="3.5" fill="#FB3640" />
      </svg>

      {showWordmark && (
        <div className="flex flex-col justify-center leading-none">
          <div className="font-mono font-black tracking-widest text-[#FB3640] text-sm md:text-base uppercase flex items-center gap-1.5">
            <span>SNARESIGHT</span>
          </div>
          <div className="text-[9px] font-mono uppercase tracking-[0.25em] text-[#FB3640]/60 mt-0.5">
            Deception Platform
          </div>
        </div>
      )}
    </div>
  );
};

export default BrandLogo;
