import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ScenarioMeta,
  ScenarioType,
  DatasetSize,
  ScenarioRunResponse,
  EvaluationSummaryResponse,
  DemoCleanupResponse,
} from '../../types/demo';
import { demoApi } from '../../services/demoApi';

export const DemonstrationControlPage: React.FC = () => {
  const [scenarios, setScenarios] = useState<ScenarioMeta[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<ScenarioType>('SCENARIO_A');
  const [datasetSize, setDatasetSize] = useState<DatasetSize>('SMALL');
  const [seed, setSeed] = useState<number>(42);
  const [loading, setLoading] = useState<boolean>(false);
  const [runResult, setRunResult] = useState<ScenarioRunResponse | null>(null);
  const [evaluation, setEvaluation] = useState<EvaluationSummaryResponse | null>(null);
  const [evalLoading, setEvalLoading] = useState<boolean>(false);
  const [cleanupResult, setCleanupResult] = useState<DemoCleanupResponse | null>(null);
  const [cleanupLoading, setCleanupLoading] = useState<boolean>(false);
  const [confirmCleanupOpen, setConfirmCleanupOpen] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    loadScenarios();
    loadEvaluation();
  }, []);

  const loadScenarios = async () => {
    try {
      const data = await demoApi.listScenarios();
      setScenarios(data);
    } catch (err: any) {
      console.error('Failed to load scenarios:', err);
    }
  };

  const loadEvaluation = async () => {
    setEvalLoading(true);
    try {
      const data = await demoApi.getEvaluation();
      setEvaluation(data);
    } catch (err: any) {
      console.error('Failed to load evaluation:', err);
    } finally {
      setEvalLoading(false);
    }
  };

  const handleRunScenario = async () => {
    setLoading(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    setRunResult(null);
    try {
      const resp = await demoApi.runScenario({
        scenario_type: selectedScenario,
        size: datasetSize,
        seed: Number(seed),
      });
      setRunResult(resp);
      setSuccessMsg(`Demonstration executed successfully: ${resp.events_accepted} events ingested in ${resp.duration_ms}ms.`);
      await loadEvaluation();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to execute scenario');
    } finally {
      setLoading(false);
    }
  };

  const handleCleanup = async (dryRun: boolean) => {
    setCleanupLoading(true);
    setErrorMsg(null);
    try {
      const resp = await demoApi.cleanupData({ dry_run: dryRun });
      setCleanupResult(resp);
      if (!dryRun) {
        setConfirmCleanupOpen(false);
        setSuccessMsg(resp.message);
        await loadEvaluation();
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Cleanup operation failed');
    } finally {
      setCleanupLoading(false);
    }
  };

  const handleExportData = async () => {
    try {
      const data = await demoApi.exportData();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `snaresight_demo_export_${data.export_id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setErrorMsg('Failed to export demonstration data: ' + err.message);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* 1. Header with Lab Classification Banner */}
      <div className="bg-amber-950/40 border border-amber-500/40 rounded-xl p-4 flex items-start gap-4">
        <span className="text-3xl">🧪</span>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold text-amber-200 uppercase tracking-wide">
              Demonstration Lab & Synthetic Benchmark Center
            </h1>
            <span className="px-2 py-0.5 text-[10px] font-mono bg-amber-500/20 text-amber-300 rounded border border-amber-500/30">
              ISOLATED LAB DATA ONLY
            </span>
          </div>
          <p className="text-xs text-amber-300/80 mt-1 leading-relaxed">
            All telemetry and attack vectors generated in this module are purely synthetic, deterministic, and contained
            strictly within local loopback decoys (RFC 5737 test subnets). No external hosts or production environments
            are contacted. Zero raw passwords or credentials are ever ingested or persisted.
          </p>
        </div>
      </div>

      {/* 2. Quick Navigation Shortcut Pills */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-slate-400 font-medium mr-1">SOC Cross-Module Links:</span>
        <Link
          to="/alerts"
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors"
        >
          <span>🚨</span> Alert Management
        </Link>
        <Link
          to="/events"
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors"
        >
          <span>🛡️</span> Security Events
        </Link>
        <Link
          to="/sessions"
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors"
        >
          <span>⏱️</span> Session Explorer
        </Link>
        <Link
          to="/mitre"
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors"
        >
          <span>🗺️</span> MITRE ATT&CK
        </Link>
        <Link
          to="/response"
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors"
        >
          <span>🛡️</span> Defensive Response
        </Link>
        <Link
          to="/health"
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors"
        >
          <span>🩺</span> Platform Health
        </Link>
      </div>

      {/* Notifications */}
      {errorMsg && (
        <div className="p-3 bg-rose-950/50 border border-rose-500/50 rounded-lg text-rose-300 text-xs flex justify-between items-center">
          <span>⚠️ {errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-rose-400 hover:text-rose-200">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-3 bg-emerald-950/50 border border-emerald-500/50 rounded-lg text-emerald-300 text-xs flex justify-between items-center">
          <span>✓ {successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200">✕</button>
        </div>
      )}

      {/* 3. Scenario Selection and Execution Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Scenarios Grid */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
            <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider mb-3">
              1. Select Demonstration Scenario
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {scenarios.map((sc) => {
                const isSelected = selectedScenario === sc.scenario_id;
                return (
                  <div
                    key={sc.scenario_id}
                    onClick={() => setSelectedScenario(sc.scenario_id)}
                    className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-blue-950/40 border-blue-500 text-slate-100 shadow-md ring-1 ring-blue-500/50'
                        : 'bg-slate-950/50 border-slate-800 hover:border-slate-700 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-xs tracking-wide">{sc.title}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                        {sc.target_decoy}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1.5 line-clamp-2 leading-relaxed">
                      {sc.description}
                    </p>
                    <div className="flex flex-wrap gap-1 mt-2.5">
                      {sc.mitre_techniques.map((tech) => (
                        <span
                          key={tech}
                          className="px-1.5 py-0.5 text-[9px] font-mono rounded bg-purple-950/60 text-purple-300 border border-purple-800/50"
                        >
                          {tech}
                        </span>
                      ))}
                      {sc.expected_rules.map((rule) => (
                        <span
                          key={rule}
                          className="px-1.5 py-0.5 text-[9px] font-mono rounded bg-amber-950/60 text-amber-300 border border-amber-800/50"
                        >
                          {rule}
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Col: Configuration & Run Controls */}
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">
              2. Execution Parameters
            </h2>

            {/* Dataset Size */}
            <div>
              <label className="block text-xs text-slate-400 font-medium mb-1.5">Telemetry Scale</label>
              <div className="grid grid-cols-3 gap-2">
                {(['SMALL', 'MEDIUM', 'LARGE'] as DatasetSize[]).map((sz) => (
                  <button
                    key={sz}
                    type="button"
                    onClick={() => setDatasetSize(sz)}
                    className={`py-2 text-xs font-semibold rounded-lg border transition-all ${
                      datasetSize === sz
                        ? 'bg-blue-600 border-blue-500 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sz === 'SMALL' ? 'Small (~25)' : sz === 'MEDIUM' ? 'Medium (~100)' : 'Large (~500)'}
                  </button>
                ))}
              </div>
            </div>

            {/* Seed */}
            <div>
              <label className="block text-xs text-slate-400 font-medium mb-1.5">
                Deterministic PRNG Seed
              </label>
              <input
                type="number"
                min={1}
                max={999999}
                value={seed}
                onChange={(e) => setSeed(Number(e.target.value) || 42)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Using the same seed produces identical timestamps, IPs, and event sequences.
              </span>
            </div>

            {/* Execute Button */}
            <button
              onClick={handleRunScenario}
              disabled={loading}
              className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-all shadow-md flex items-center justify-center gap-2 cursor-pointer"
            >
              {loading ? (
                <>
                  <span className="animate-spin text-sm">⏳</span> Ingesting Telemetry & Evaluating...
                </>
              ) : (
                <>
                  <span>🚀</span> Launch Synthetic Scenario
                </>
              )}
            </button>
          </div>

          {/* Quick Actions Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Telemetry Export & Clean
            </h2>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={handleExportData}
                className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg border border-slate-700 font-medium transition-colors cursor-pointer"
              >
                📥 Export JSON
              </button>
              <button
                onClick={() => handleCleanup(true)}
                disabled={cleanupLoading}
                className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg border border-slate-700 font-medium transition-colors cursor-pointer"
              >
                🔍 Audit Records
              </button>
            </div>
            <button
              onClick={() => setConfirmCleanupOpen(true)}
              className="w-full py-2 bg-rose-950/40 hover:bg-rose-900/40 border border-rose-800/50 text-rose-300 text-xs rounded-lg font-medium transition-colors cursor-pointer"
            >
              🗑️ Safe Demo Cleanup
            </button>
          </div>
        </div>
      </div>

      {/* 4. Live Execution Outcome Card */}
      {runResult && (
        <div className="bg-slate-900 border border-emerald-500/40 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5">
              <span className="text-xl">✅</span>
              <div>
                <h3 className="font-semibold text-sm text-slate-100">
                  Run Execution Output — {runResult.run_id}
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">{runResult.summary}</p>
              </div>
            </div>
            <span className="px-2.5 py-1 text-xs font-mono font-bold rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
              {runResult.status}
            </span>
          </div>

          {/* Key Metrics Chips */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase font-mono">Generated</div>
              <div className="text-base font-bold text-slate-200 mt-0.5">{runResult.events_generated}</div>
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase font-mono">Accepted</div>
              <div className="text-base font-bold text-emerald-400 mt-0.5">{runResult.events_accepted}</div>
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase font-mono">Detections</div>
              <div className="text-base font-bold text-amber-400 mt-0.5">{runResult.detections_triggered}</div>
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase font-mono">Alerts Created</div>
              <div className="text-base font-bold text-blue-400 mt-0.5">{runResult.alerts_created}</div>
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase font-mono">Sessions</div>
              <div className="text-base font-bold text-purple-400 mt-0.5">{runResult.sessions_created}</div>
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase font-mono">Execution Time</div>
              <div className="text-base font-bold text-cyan-400 mt-0.5">{runResult.duration_ms} ms</div>
            </div>
          </div>

          {/* Scenario E Escalation Details */}
          {runResult.details?.escalated_case_id && (
            <div className="p-3 bg-blue-950/30 border border-blue-800/40 rounded-lg flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 text-blue-200">
                <span>🛡️</span>
                <span>
                  Escalated to Defensive Case <strong>{runResult.details.escalated_case_id}</strong> with Evidence Hold{' '}
                  <strong>{runResult.details.evidence_hold_id}</strong>.
                </span>
              </div>
              <Link
                to="/response"
                className="px-2.5 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-[11px] font-medium"
              >
                View in Response Center →
              </Link>
            </div>
          )}
        </div>
      )}

      {/* 5. Detection Quality & Evaluation Metrics */}
      {evaluation && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">
                Threat Detection Quality & Benchmark Evaluation
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Empirical True Positive vs. Ground Truth validation across active detection scenarios.
              </p>
            </div>
            <button
              onClick={loadEvaluation}
              disabled={evalLoading}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700 cursor-pointer"
            >
              🔄 Refresh
            </button>
          </div>

          {/* 4 KPI Progress Bars */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
              <div className="flex justify-between text-xs font-medium">
                <span className="text-slate-400">Precision</span>
                <span className="text-emerald-400 font-bold font-mono">
                  {(evaluation.overall_precision * 100).toFixed(1)}%
                </span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full mt-2 overflow-hidden">
                <div
                  className="bg-emerald-500 h-2 rounded-full transition-all"
                  style={{ width: `${evaluation.overall_precision * 100}%` }}
                />
              </div>
              <span className="text-[10px] text-slate-500 mt-1 block">TP / (TP + FP)</span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
              <div className="flex justify-between text-xs font-medium">
                <span className="text-slate-400">Recall</span>
                <span className="text-blue-400 font-bold font-mono">
                  {(evaluation.overall_recall * 100).toFixed(1)}%
                </span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full mt-2 overflow-hidden">
                <div
                  className="bg-blue-500 h-2 rounded-full transition-all"
                  style={{ width: `${evaluation.overall_recall * 100}%` }}
                />
              </div>
              <span className="text-[10px] text-slate-500 mt-1 block">TP / (TP + FN)</span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
              <div className="flex justify-between text-xs font-medium">
                <span className="text-slate-400">F1 Score</span>
                <span className="text-purple-400 font-bold font-mono">
                  {(evaluation.overall_f1_score * 100).toFixed(1)}%
                </span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full mt-2 overflow-hidden">
                <div
                  className="bg-purple-500 h-2 rounded-full transition-all"
                  style={{ width: `${evaluation.overall_f1_score * 100}%` }}
                />
              </div>
              <span className="text-[10px] text-slate-500 mt-1 block">Harmonic Mean</span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
              <div className="flex justify-between text-xs font-medium">
                <span className="text-slate-400">Mean Latency</span>
                <span className="text-cyan-400 font-bold font-mono">
                  {evaluation.average_processing_latency_ms} ms
                </span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full mt-2 overflow-hidden">
                <div
                  className="bg-cyan-500 h-2 rounded-full transition-all"
                  style={{ width: `${Math.min(100, evaluation.average_processing_latency_ms * 10)}%` }}
                />
              </div>
              <span className="text-[10px] text-slate-500 mt-1 block">Per Telemetry Event</span>
            </div>
          </div>

          {/* Per-Rule Breakdown Table */}
          {evaluation.rules_evaluated?.length > 0 && (
            <div className="overflow-x-auto border border-slate-800 rounded-lg">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950 text-slate-400 font-mono text-[11px] uppercase border-b border-slate-800">
                  <tr>
                    <th className="p-2.5">Rule ID</th>
                    <th className="p-2.5">Rule Name</th>
                    <th className="p-2.5 text-center">True Positives</th>
                    <th className="p-2.5 text-center">False Positives</th>
                    <th className="p-2.5 text-center">False Negatives</th>
                    <th className="p-2.5 text-right">Precision</th>
                    <th className="p-2.5 text-right">Recall</th>
                    <th className="p-2.5 text-right">F1 Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {evaluation.rules_evaluated.map((r) => (
                    <tr key={r.rule_id} className="hover:bg-slate-800/30">
                      <td className="p-2.5 font-mono text-amber-300 font-semibold">{r.rule_id}</td>
                      <td className="p-2.5 text-slate-200">{r.rule_name}</td>
                      <td className="p-2.5 text-center text-emerald-400 font-mono">{r.true_positives}</td>
                      <td className="p-2.5 text-center text-rose-400 font-mono">{r.false_positives}</td>
                      <td className="p-2.5 text-center text-slate-400 font-mono">{r.false_negatives}</td>
                      <td className="p-2.5 text-right font-mono text-emerald-400">
                        {(r.precision * 100).toFixed(1)}%
                      </td>
                      <td className="p-2.5 text-right font-mono text-blue-400">
                        {(r.recall * 100).toFixed(1)}%
                      </td>
                      <td className="p-2.5 text-right font-mono text-purple-400 font-semibold">
                        {(r.f1_score * 100).toFixed(1)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Evaluation Notes */}
          <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 text-[11px] text-slate-400 space-y-1">
            {evaluation.evaluation_notes?.map((note, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <span className="text-emerald-400">✓</span> {note}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 6. Cleanup Audit Modal */}
      {confirmCleanupOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3 text-rose-400">
              <span className="text-2xl">⚠️</span>
              <h3 className="font-bold text-base text-slate-100">Confirm Demonstration Telemetry Cleanup</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              This action will permanently delete all synthetic demonstration events and associated demonstration alerts.
              Records tied to active <strong>Evidence Preservation Holds</strong> are strictly protected and will remain
              intact.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setConfirmCleanupOpen(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded-lg font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => handleCleanup(false)}
                disabled={cleanupLoading}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs rounded-lg font-semibold cursor-pointer"
              >
                {cleanupLoading ? 'Cleaning...' : 'Purge Synthetic Records'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DemonstrationControlPage;

