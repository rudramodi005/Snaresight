# Scoring Calibration Limitations and Performance

## 1. Performance Measurements

- **Evidence Quality Assessment**: `~0.04 ms` per detection result.
- **Severity Evaluation**: `~0.03 ms`.
- **Confidence Calculation**: `~0.05 ms`.
- **Complete Threat Assessment Pipeline**: `~0.15 ms` end-to-end.
- **Reassessment / Analyst Review Overhead**: `~0.08 ms`.

## 2. Calibration Limitations

1. **Evidence Quality vs. Real-World Probability**:
   - The confidence score (0–100) measures **telemetry completeness, schema validity, and internal corroboration**.
   - A confidence score of `90` does **not** signify a `90%` mathematical probability of an ongoing enterprise breach.
2. **Provisional Scoring Parameters**:
   - Current weights in `DEFAULT_SCORING_POLICY` (v1.0) represent engineering baselines.
   - Future statistical calibration requires an empirical labeled dataset collected across diverse honeypot environments.
3. **No Automated Attribution**:
   - Assessments evaluate observed behavior and interaction telemetry only. They do not attribute activity to specific threat actors or real-world entities.

