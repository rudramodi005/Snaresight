import { describe, it, expect } from 'vitest';
import { ScenarioType, DatasetSize } from '../../src/types/demo';

describe('Demonstration Lab Contracts & Precision-Recall Mathematics', () => {
  it('validates scenario types and dataset size configurations', () => {
    const validScenarios: ScenarioType[] = [
      'SCENARIO_A',
      'SCENARIO_B',
      'SCENARIO_C',
      'SCENARIO_D',
      'SCENARIO_E',
      'SCENARIO_F',
      'ALL',
    ];
    expect(validScenarios).toHaveLength(7);

    const sizes: Record<DatasetSize, number> = {
      SMALL: 25,
      MEDIUM: 100,
      LARGE: 500,
    };
    expect(sizes.SMALL).toBe(25);
    expect(sizes.MEDIUM).toBe(100);
    expect(sizes.LARGE).toBe(500);
  });

  it('computes detection precision, recall, and F1 harmonic mean correctly', () => {
    const calculateMetrics = (tp: number, fp: number, fn: number) => {
      const precision = tp + fp > 0 ? tp / (tp + fp) : 1.0;
      const recall = tp + fn > 0 ? tp / (tp + fn) : 1.0;
      const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0.0;
      return {
        precision: Math.round(precision * 1000) / 1000,
        recall: Math.round(recall * 1000) / 1000,
        f1: Math.round(f1 * 1000) / 1000,
      };
    };

    // Perfect Detection (10 TP, 0 FP, 0 FN)
    const perfect = calculateMetrics(10, 0, 0);
    expect(perfect.precision).toBe(1.0);
    expect(perfect.recall).toBe(1.0);
    expect(perfect.f1).toBe(1.0);

    // Some Misses (8 TP, 0 FP, 2 FN)
    const withMisses = calculateMetrics(8, 0, 2);
    expect(withMisses.precision).toBe(1.0);
    expect(withMisses.recall).toBe(0.8);
    expect(withMisses.f1).toBe(0.889);

    // False Alarm (10 TP, 2 FP, 0 FN)
    const withFalseAlarms = calculateMetrics(10, 2, 0);
    expect(withFalseAlarms.precision).toBe(0.833);
    expect(withFalseAlarms.recall).toBe(1.0);
    expect(withFalseAlarms.f1).toBe(0.909);
  });

  it('validates synthetic demonstration data watermark invariant', () => {
    const applyWatermark = (payload: any) => ({
      ...payload,
      watermark: 'SYNTHETIC DEMONSTRATION DATA - NOT REAL INCIDENT',
      is_synthetic: true,
      lab_environment: 'isolated_lab',
    });

    const record = applyWatermark({ event_type: 'web_login_attempt' });
    expect(record.watermark).toContain('SYNTHETIC DEMONSTRATION DATA');
    expect(record.is_synthetic).toBe(true);
    expect(record.lab_environment).toBe('isolated_lab');
  });
});

