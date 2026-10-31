/**
 * SnareSight Strict Brand Theme System.
 * 
 * Primary Background: #000F08 (Obsidian Void)
 * Primary Accent:     #FB3640 (Snare Crimson)
 * 
 * Strict Constraint: Zero third color across all UI, typography, charts, and visualizations.
 */

export const BRAND_COLORS = {
  bg: '#000F08',
  crimson: '#FB3640',
} as const;

/**
 * Returns a hex/rgba tonal string derived exclusively from #FB3640 with the given opacity.
 */
export function crimson(alpha: number = 1.0): string {
  const clamped = Math.max(0, Math.min(1, alpha));
  return `rgba(251, 54, 64, ${clamped})`;
}

/**
 * Returns a hex/rgba tonal string derived exclusively from #000F08 with the given opacity.
 */
export function obsidian(alpha: number = 1.0): string {
  const clamped = Math.max(0, Math.min(1, alpha));
  return `rgba(0, 15, 8, ${clamped})`;
}

/**
 * Recharts Color & Styling Configuration for SnareSight.
 * Guaranteed 100% compliant with the two-color brand constraint.
 */
export const CHART_THEME = {
  stroke: BRAND_COLORS.crimson,
  strokeMuted: crimson(0.4),
  strokeDim: crimson(0.18),
  fill: crimson(0.12),
  fillHover: crimson(0.25),
  grid: crimson(0.08),
  tick: crimson(0.6),
  tooltip: {
    contentStyle: {
      backgroundColor: BRAND_COLORS.bg,
      borderColor: crimson(0.3),
      borderRadius: '8px',
      color: BRAND_COLORS.crimson,
      fontSize: '11px',
      fontFamily: 'ui-monospace, monospace',
      boxShadow: '0 4px 20px rgba(251, 54, 64, 0.25)',
    },
    itemStyle: {
      color: BRAND_COLORS.crimson,
    },
    labelStyle: {
      color: crimson(0.75),
      fontWeight: 600,
    },
  },
};

