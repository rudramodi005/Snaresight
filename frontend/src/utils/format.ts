/**
 * Safe numeric and string formatting utilities for SnareSight.
 *
 * Prevents TypeError crashes from `.toFixed()` on null, undefined, or non-numeric values.
 */

/**
 * Safely checks if a value is a valid, finite number.
 */
export function isValidNumber(val: unknown): val is number {
  return typeof val === 'number' && !Number.isNaN(val) && Number.isFinite(val);
}

/**
 * Safely formats a numeric value to a fixed number of decimal places.
 * Returns fallback (default: 'N/A') when input is null, undefined, NaN, or non-numeric.
 *
 * @param val The value to format.
 * @param digits Number of digits after the decimal point (default: 1).
 * @param fallback String returned when value is invalid (default: 'N/A').
 */
export function formatNumber(
  val: unknown,
  digits: number = 1,
  fallback: string = 'N/A'
): string {
  if (!isValidNumber(val)) {
    return fallback;
  }
  return val.toFixed(digits);
}

/**
 * Safely formats a numeric ratio or percentage.
 *
 * @param val The percentage or ratio value.
 * @param digits Decimal places (default: 1).
 * @param fallback String returned when value is invalid (default: 'N/A').
 * @param multiplier Multiply value before formatting (e.g. 100 for ratios 0.0-1.0, 1 for already percentage values).
 */
export function formatPercent(
  val: unknown,
  digits: number = 1,
  fallback: string = 'N/A',
  multiplier: number = 1
): string {
  if (!isValidNumber(val)) {
    return fallback;
  }
  const computed = val * multiplier;
  if (!isValidNumber(computed)) {
    return fallback;
  }
  return `${computed.toFixed(digits)}%`;
}

/**
 * Safely performs division without dividing by zero or producing NaN/Infinity.
 */
export function safeDivide(
  numerator: unknown,
  denominator: unknown,
  fallback: number = 0
): number {
  if (!isValidNumber(numerator) || !isValidNumber(denominator) || denominator === 0) {
    return fallback;
  }
  const result = numerator / denominator;
  return isValidNumber(result) ? result : fallback;
}

