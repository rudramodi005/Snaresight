import { describe, it, expect } from 'vitest';
import {
  isValidNumber,
  formatNumber,
  formatPercent,
  safeDivide,
  formatInteger,
  formatDateTime,
} from '../../src/utils/format';

describe('Numeric Safety & Formatting Utilities', () => {
  describe('isValidNumber', () => {
    it('returns true for genuine finite numbers', () => {
      expect(isValidNumber(0)).toBe(true);
      expect(isValidNumber(42)).toBe(true);
      expect(isValidNumber(-3.1415)).toBe(true);
      expect(isValidNumber(100.0)).toBe(true);
    });

    it('returns false for null and undefined', () => {
      expect(isValidNumber(null)).toBe(false);
      expect(isValidNumber(undefined)).toBe(false);
    });

    it('returns false for NaN and infinite numbers', () => {
      expect(isValidNumber(NaN)).toBe(false);
      expect(isValidNumber(Infinity)).toBe(false);
      expect(isValidNumber(-Infinity)).toBe(false);
    });

    it('returns false for non-numeric types', () => {
      expect(isValidNumber('100')).toBe(false);
      expect(isValidNumber('')).toBe(false);
      expect(isValidNumber(true)).toBe(false);
      expect(isValidNumber({})).toBe(false);
      expect(isValidNumber([])).toBe(false);
    });
  });

  describe('formatNumber', () => {
    it('formats valid numbers with default and custom decimal places', () => {
      expect(formatNumber(42.567)).toBe('42.6');
      expect(formatNumber(42.567, 2)).toBe('42.57');
      expect(formatNumber(0, 0)).toBe('0');
      expect(formatNumber(-12.34, 1)).toBe('-12.3');
    });

    it('returns fallback for null, undefined, and NaN without throwing', () => {
      expect(formatNumber(null)).toBe('N/A');
      expect(formatNumber(undefined)).toBe('N/A');
      expect(formatNumber(NaN)).toBe('N/A');
      expect(formatNumber(undefined, 2, '...')).toBe('...');
      expect(formatNumber(null, 1, '0.0')).toBe('0.0');
    });

    it('does not crash when called with unexpected types', () => {
      expect(formatNumber('invalid')).toBe('N/A');
      expect(formatNumber({})).toBe('N/A');
    });
  });

  describe('formatPercent', () => {
    it('formats percentage values with suffix', () => {
      expect(formatPercent(99.45, 1)).toBe('99.5%');
      expect(formatPercent(100, 0)).toBe('100%');
      expect(formatPercent(0, 1)).toBe('0.0%');
    });

    it('applies multiplier when formatting ratios', () => {
      expect(formatPercent(0.852, 1, 'N/A', 100)).toBe('85.2%');
      expect(formatPercent(1.0, 0, 'N/A', 100)).toBe('100%');
    });

    it('returns fallback for missing or null values without crashing', () => {
      expect(formatPercent(null)).toBe('N/A');
      expect(formatPercent(undefined)).toBe('N/A');
      expect(formatPercent(NaN, 1, '...')).toBe('...');
      expect(formatPercent(undefined, 2, 'N/A', 100)).toBe('N/A');
    });
  });

  describe('safeDivide', () => {
    it('divides valid numbers correctly', () => {
      expect(safeDivide(10, 2)).toBe(5);
      expect(safeDivide(5, 10)).toBe(0.5);
    });

    it('safely handles zero denominator without producing Infinity', () => {
      expect(safeDivide(10, 0)).toBe(0);
      expect(safeDivide(10, 0, -1)).toBe(-1);
    });

    it('safely handles null and undefined operands', () => {
      expect(safeDivide(null, 10)).toBe(0);
      expect(safeDivide(10, undefined)).toBe(0);
      expect(safeDivide(undefined, null, 0)).toBe(0);
    });
  });

  describe('formatInteger', () => {
    it('formats valid integer numbers correctly', () => {
      expect(formatInteger(1000)).toBe('1,000');
      expect(formatInteger(0)).toBe('0');
      expect(formatInteger(1234567)).toBe('1,234,567');
    });

    it('returns fallback for null, undefined, or NaN without throwing', () => {
      expect(formatInteger(null)).toBe('0');
      expect(formatInteger(undefined)).toBe('0');
      expect(formatInteger(undefined, '...')).toBe('...');
      expect(formatInteger(NaN, 'N/A')).toBe('N/A');
    });
  });

  describe('formatDateTime', () => {
    it('formats valid dates without crashing', () => {
      const dt = new Date('2026-11-01T00:00:00Z');
      expect(formatDateTime(dt)).not.toBe('N/A');
      expect(formatDateTime('2026-11-01T00:00:00Z')).not.toBe('N/A');
    });

    it('returns fallback for null, undefined, and invalid date strings', () => {
      expect(formatDateTime(null)).toBe('N/A');
      expect(formatDateTime(undefined)).toBe('N/A');
      expect(formatDateTime('invalid-date-string')).toBe('N/A');
      expect(formatDateTime(undefined, 'Unknown')).toBe('Unknown');
    });
  });
});

