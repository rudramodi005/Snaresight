/**
 * SnareSight Sophisticated Security Palette Theme System.
 * 
 * Palette:
 * - #181A2F: Deep Midnight Slate (Primary Viewport / App Background)
 * - #242E49: Dark Slate Navy (Elevated Surfaces, Cards, Navigation, Panels)
 * - #37415C: Muted Slate Blue-Grey (Borders, Dividers, Inactive Controls)
 * - #FDA481: Peach Coral (High-Contrast Accent, Highlights, Active States, Warnings)
 * - #B4182D: Crimson Red (Primary Threat Accent, Hero Elements, Critical CTAs)
 * - #54162B: Deep Maroon / Wine (Dark Threat Backdrops, Critical Badges)
 */

export const BRAND_COLORS = {
  bg: '#181A2F',            // Deep Midnight Slate
  surface: '#242E49',       // Dark Slate Navy
  border: '#37415C',        // Slate Blue-Grey
  peach: '#FDA481',         // Peach Coral
  crimson: '#B4182D',       // Crimson Red
  wine: '#54162B',          // Deep Maroon
} as const;

export function crimson(alpha: number = 1.0): string {
  const clamped = Math.max(0, Math.min(1, alpha));
  return `rgba(180, 24, 45, ${clamped})`;
}

export function peach(alpha: number = 1.0): string {
  const clamped = Math.max(0, Math.min(1, alpha));
  return `rgba(253, 164, 129, ${clamped})`;
}

export function surface(alpha: number = 1.0): string {
  const clamped = Math.max(0, Math.min(1, alpha));
  return `rgba(36, 46, 73, ${clamped})`;
}

export function border(alpha: number = 1.0): string {
  const clamped = Math.max(0, Math.min(1, alpha));
  return `rgba(55, 65, 92, ${clamped})`;
}

export function wine(alpha: number = 1.0): string {
  const clamped = Math.max(0, Math.min(1, alpha));
  return `rgba(84, 22, 43, ${clamped})`;
}

export function midnight(alpha: number = 1.0): string {
  const clamped = Math.max(0, Math.min(1, alpha));
  return `rgba(24, 26, 47, ${clamped})`;
}

// Backward-compatibility aliases
export const obsidian = midnight;

export const CHART_THEME = {
  stroke: BRAND_COLORS.crimson,
  strokeSecondary: BRAND_COLORS.peach,
  strokeMuted: BRAND_COLORS.border,
  strokeDim: border(0.4),
  fill: crimson(0.15),
  fillHover: crimson(0.3),
  fillCrimson: crimson(0.2),
  fillPeach: peach(0.2),
  grid: border(0.4),
  tick: BRAND_COLORS.border,
  tooltip: {
    contentStyle: {
      backgroundColor: BRAND_COLORS.surface,
      borderColor: BRAND_COLORS.border,
      borderRadius: '8px',
      color: '#FFFFFF',
      fontSize: '11px',
      fontFamily: 'ui-monospace, monospace',
      boxShadow: '0 4px 20px rgba(24, 26, 47, 0.6)',
    },
    itemStyle: {
      color: BRAND_COLORS.peach,
    },
    labelStyle: {
      color: '#FFFFFF',
      fontWeight: 600,
    },
  },
};
