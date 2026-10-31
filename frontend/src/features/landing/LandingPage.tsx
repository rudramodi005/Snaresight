/**
 * SnareSight Enterprise Public Landing Page.
 * 
 * Strict Brand Identity:
 * Background: #000F08 (Obsidian Void)
 * Accent:     #FB3640 (Snare Crimson)
 * 
 * Zero third color used anywhere.
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import BrandLogo from '../../components/common/BrandLogo';

export const LandingPage: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'matrix' | 'correlation' | 'sensors'>('matrix');
  const [privacyModalOpen, setPrivacyModalOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Smooth scroll helper
  const scrollTo = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="min-h-screen bg-[#000F08] text-[#FB3640] font-sans selection:bg-[#FB3640] selection:text-[#000F08]">
      {/* ==================================================================== */}
      {/* 1. STICKY NAVIGATION BAR */}
      {/* ==================================================================== */}
      <header className="sticky top-0 z-50 bg-[#000F08]/95 backdrop-blur-md border-b border-[#FB3640]/20 px-4 sm:px-6 py-3 sm:py-4 flex items-center justify-between">
        <div className="flex items-center gap-4 sm:gap-8">
          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="lg:hidden w-8 h-8 rounded-lg bg-[#000F08] border border-[#FB3640]/30 hover:border-[#FB3640] flex items-center justify-center text-xs text-[#FB3640]"
            aria-label="Toggle section menu"
          >
            {mobileMenuOpen ? '✕' : '☰'}
          </button>

          <button onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })} className="text-left">
            <BrandLogo size="md" showWordmark={true} />
          </button>

          <nav className="hidden lg:flex items-center gap-6 text-xs font-mono tracking-wider">
            <button onClick={() => scrollTo('problem')} className="text-[#FB3640]/80 hover:text-[#FB3640] transition-colors">
              OVERVIEW
            </button>
            <button onClick={() => scrollTo('capabilities')} className="text-[#FB3640]/80 hover:text-[#FB3640] transition-colors">
              CAPABILITIES
            </button>
            <button onClick={() => scrollTo('workflow')} className="text-[#FB3640]/80 hover:text-[#FB3640] transition-colors">
              HOW IT WORKS
            </button>
            <button onClick={() => scrollTo('mitre')} className="text-[#FB3640]/80 hover:text-[#FB3640] transition-colors">
              MITRE ATT&CK
            </button>
            <button onClick={() => scrollTo('preview')} className="text-[#FB3640]/80 hover:text-[#FB3640] transition-colors">
              SOC PREVIEW
            </button>
            <button onClick={() => scrollTo('architecture')} className="text-[#FB3640]/80 hover:text-[#FB3640] transition-colors">
              ARCHITECTURE
            </button>
          </nav>
        </div>

        <div className="flex items-center gap-2 sm:gap-3">
          <button
            onClick={() => navigate('/login')}
            className="px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg border border-[#FB3640]/30 hover:border-[#FB3640] hover:bg-[#FB3640]/10 text-[11px] sm:text-xs font-mono tracking-wider transition-all whitespace-nowrap"
          >
            SIGN IN
          </button>
          <button
            onClick={() => navigate('/app')}
            className="px-3 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-[#FB3640] text-[#000F08] hover:bg-[#FB3640]/90 font-mono font-bold text-[11px] sm:text-xs tracking-wider transition-all shadow-[0_0_15px_rgba(251,54,64,0.35)] whitespace-nowrap"
          >
            LAUNCH SOC
          </button>
        </div>

        {/* Mobile Navigation Dropdown */}
        {mobileMenuOpen && (
          <div className="lg:hidden absolute top-full left-0 right-0 bg-[#000F08] border-b border-[#FB3640]/30 p-4 space-y-1 shadow-crimson-lg">
            {[
              { id: 'problem', label: 'Overview' },
              { id: 'capabilities', label: 'Capabilities' },
              { id: 'workflow', label: 'How It Works' },
              { id: 'mitre', label: 'MITRE ATT&CK' },
              { id: 'preview', label: 'SOC Preview' },
              { id: 'architecture', label: 'Architecture' },
            ].map((item) => (
              <button
                key={item.id}
                onClick={() => {
                  scrollTo(item.id);
                  setMobileMenuOpen(false);
                }}
                className="block w-full text-left py-2 px-3 rounded text-xs font-mono tracking-wider text-[#FB3640]/80 hover:text-[#FB3640] hover:bg-[#FB3640]/10 uppercase"
              >
                {item.label}
              </button>
            ))}
          </div>
        )}
      </header>

      {/* ==================================================================== */}
      {/* 2. HERO SECTION */}
      {/* ==================================================================== */}
      <section className="relative px-6 pt-20 pb-28 max-w-7xl mx-auto overflow-hidden">
        {/* Subtle Deception Grid Background Overlay */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(251,54,64,0.12),transparent_70%)] pointer-events-none" />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center relative z-10">
          <div className="lg:col-span-7 space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[#FB3640]/30 bg-[#FB3640]/5 text-[11px] font-mono tracking-widest uppercase">
              <span className="w-2 h-2 rounded-full bg-[#FB3640] animate-pulse" />
              DECEPTION-DRIVEN THREAT DETECTION & SECURITY OPERATIONS
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight leading-[1.08] uppercase">
              See The Threat <br />
              <span className="text-[#FB3640] underline decoration-[#FB3640]/40 decoration-wavy">
                Before It Sees You.
              </span>
            </h1>

            <p className="text-sm sm:text-base text-[#FB3640]/80 font-mono leading-relaxed max-w-2xl">
              Turn deception into intelligence. SnareSight captures suspicious interactions, correlates
              attacker activity and transforms honeypot telemetry into actionable security insights.
            </p>

            <div className="flex flex-wrap items-center gap-4 pt-4">
              <button
                onClick={() => navigate('/app')}
                className="px-6 py-3.5 rounded-lg bg-[#FB3640] text-[#000F08] font-mono font-bold text-xs uppercase tracking-wider hover:bg-[#FB3640]/90 shadow-[0_0_25px_rgba(251,54,64,0.4)] transition-all"
              >
                Launch Security Dashboard →
              </button>
              <button
                onClick={() => scrollTo('capabilities')}
                className="px-6 py-3.5 rounded-lg border border-[#FB3640]/40 hover:border-[#FB3640] hover:bg-[#FB3640]/10 font-mono font-semibold text-xs uppercase tracking-wider text-[#FB3640] transition-all"
              >
                Explore the Platform
              </button>
            </div>

            <div className="grid grid-cols-3 gap-4 pt-8 border-t border-[#FB3640]/15 font-mono">
              <div>
                <div className="text-2xl font-bold text-[#FB3640]">100%</div>
                <div className="text-[10px] uppercase text-[#FB3640]/60 tracking-wider mt-0.5">Zero-False-Positive Decoy Telemetry</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-[#FB3640]">v14.1</div>
                <div className="text-[10px] uppercase text-[#FB3640]/60 tracking-wider mt-0.5">MITRE ATT&CK Matrix Alignment</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-[#FB3640]">74+</div>
                <div className="text-[10px] uppercase text-[#FB3640]/60 tracking-wider mt-0.5">Correlated Forensic Entities</div>
              </div>
            </div>
          </div>

          {/* Interactive Cybersecurity Topology Visual */}
          <div className="lg:col-span-5 relative">
            <div className="relative p-6 rounded-2xl border border-[#FB3640]/30 bg-[#FB3640]/[0.02] shadow-[0_0_40px_rgba(251,54,64,0.12)]">
              {/* Radar Coordinate Frame */}
              <div className="flex items-center justify-between pb-3 border-b border-[#FB3640]/20 text-[10px] font-mono text-[#FB3640]/70">
                <span className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 bg-[#FB3640] rounded-full animate-ping" />
                  SNARE DECEPTION GRID // SECTOR-01
                </span>
                <span>STATUS: ARMED</span>
              </div>

              {/* Threat Mesh SVG Graphic */}
              <div className="py-6 flex items-center justify-center">
                <svg viewBox="0 0 400 320" className="w-full h-auto max-w-sm" fill="none" xmlns="http://www.w3.org/2000/svg">
                  {/* Concentric radar rings */}
                  <circle cx="200" cy="160" r="140" stroke="#FB3640" strokeWidth="1" strokeOpacity="0.15" strokeDasharray="4 4" />
                  <circle cx="200" cy="160" r="95" stroke="#FB3640" strokeWidth="1" strokeOpacity="0.25" />
                  <circle cx="200" cy="160" r="50" stroke="#FB3640" strokeWidth="1" strokeOpacity="0.4" />

                  {/* Crosshairs */}
                  <line x1="200" y1="10" x2="200" y2="310" stroke="#FB3640" strokeWidth="1" strokeOpacity="0.2" />
                  <line x1="50" y1="160" x2="350" y2="160" stroke="#FB3640" strokeWidth="1" strokeOpacity="0.2" />

                  {/* Telemetry vector streams (crimson arcs) */}
                  <path d="M 80 80 Q 140 120 200 160" stroke="#FB3640" strokeWidth="2" strokeOpacity="0.8" />
                  <path d="M 320 90 Q 260 130 200 160" stroke="#FB3640" strokeWidth="2" strokeOpacity="0.8" strokeDasharray="3 3" />
                  <path d="M 280 250 Q 240 200 200 160" stroke="#FB3640" strokeWidth="1.5" strokeOpacity="0.6" />
                  <path d="M 110 240 Q 160 200 200 160" stroke="#FB3640" strokeWidth="1.5" strokeOpacity="0.6" strokeDasharray="5 5" />

                  {/* Core Deception Singularity Node */}
                  <circle cx="200" cy="160" r="14" fill="#FB3640" />
                  <circle cx="200" cy="160" r="22" stroke="#FB3640" strokeWidth="2" strokeOpacity="0.6" />
                  <text x="200" y="195" fill="#FB3640" fontSize="10" fontFamily="monospace" textAnchor="middle" fontWeight="bold">
                    CORRELATION CORE
                  </text>

                  {/* Decoy Sensor Nodes */}
                  <g>
                    <circle cx="80" cy="80" r="8" fill="#FB3640" fillOpacity="0.3" stroke="#FB3640" strokeWidth="2" />
                    <text x="80" y="65" fill="#FB3640" fontSize="9" fontFamily="monospace" textAnchor="middle">WEB-001 (HTTP)</text>
                  </g>
                  <g>
                    <circle cx="320" cy="90" r="8" fill="#FB3640" fillOpacity="0.3" stroke="#FB3640" strokeWidth="2" />
                    <text x="320" y="75" fill="#FB3640" fontSize="9" fontFamily="monospace" textAnchor="middle">SSH-001 (Cowrie)</text>
                  </g>
                  <g>
                    <circle cx="280" cy="250" r="8" fill="#FB3640" fillOpacity="0.3" stroke="#FB3640" strokeWidth="2" />
                    <text x="280" y="275" fill="#FB3640" fontSize="9" fontFamily="monospace" textAnchor="middle">SMB-002 (Decoy)</text>
                  </g>
                  <g>
                    <circle cx="110" cy="240" r="8" fill="#FB3640" fillOpacity="0.3" stroke="#FB3640" strokeWidth="2" />
                    <text x="110" y="265" fill="#FB3640" fontSize="9" fontFamily="monospace" textAnchor="middle">API-003 (Gateway)</text>
                  </g>
                </svg>
              </div>

              {/* Feed ticker */}
              <div className="pt-3 border-t border-[#FB3640]/20 flex items-center justify-between text-[11px] font-mono text-[#FB3640]/80">
                <span>INTRUSION INTERCEPT: T1110.001</span>
                <span className="font-bold text-[#FB3640] uppercase">DETECTED</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* 3. TRUST & PROBLEM INTRODUCTION */}
      {/* ==================================================================== */}
      <section id="problem" className="py-20 border-t border-[#FB3640]/15 bg-[#FB3640]/[0.01]">
        <div className="max-w-7xl mx-auto px-6">
          <div className="max-w-3xl space-y-4">
            <div className="text-xs font-mono uppercase tracking-widest text-[#FB3640]/70">
              // THE THREAT ASYMMETRY PROBLEM
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold uppercase tracking-tight">
              Traditional Perimeter Defense Is Blind To Silent Reconnaissance.
            </h2>
            <p className="text-sm text-[#FB3640]/80 font-mono leading-relaxed">
              Modern adversaries spend days enumerating endpoints, testing default credentials, and analyzing
              attack surfaces before launching an exploit. Production logs are flooded with noisy legitimate traffic,
              making pre-attack tradecraft impossible to isolate without overwhelming SOC teams.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-12 font-mono">
            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#000F08] space-y-3">
              <div className="text-2xl font-bold text-[#FB3640]">01</div>
              <h3 className="text-base font-bold uppercase text-[#FB3640]">Deterministic Signals</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                Decoy honeypot assets serve zero production users. Any inbound interaction is inherently unauthorized,
                providing deterministic high-fidelity alerts with zero heuristic noise.
              </p>
            </div>

            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#000F08] space-y-3">
              <div className="text-2xl font-bold text-[#FB3640]">02</div>
              <h3 className="text-base font-bold uppercase text-[#FB3640]">Behavioral Association</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                SnareSight correlates rapid attempts across sessions and protocols, stitching fragmented IP interactions
                into cohesive multi-stage threat campaigns.
              </p>
            </div>

            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#000F08] space-y-3">
              <div className="text-2xl font-bold text-[#FB3640]">03</div>
              <h3 className="text-base font-bold uppercase text-[#FB3640]">Evidence-Backed MITRE</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                Technique classifications require tangible telemetry evidence. Every mapped tactic is backed by
                verifiable raw packets, HTTP payloads, and credential attempt parameters.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* 4. PLATFORM CAPABILITIES (8 Core Features) */}
      {/* ==================================================================== */}
      <section id="capabilities" className="py-24 border-t border-[#FB3640]/15">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center max-w-2xl mx-auto space-y-3">
            <div className="text-xs font-mono uppercase tracking-widest text-[#FB3640]/70">
              // PLATFORM CAPABILITIES
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold uppercase tracking-tight">
              Enterprise Defense Capabilities
            </h2>
            <p className="text-xs sm:text-sm text-[#FB3640]/70 font-mono">
              Eight dedicated deception-engineering subsystems working seamlessly across your defense infrastructure.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mt-16 font-mono">
            {/* Capability 1 */}
            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.02] hover:border-[#FB3640]/50 transition-all space-y-3">
              <div className="w-10 h-10 rounded-lg border border-[#FB3640]/40 flex items-center justify-center font-bold text-sm bg-[#FB3640]/10">
                01
              </div>
              <h3 className="text-sm font-bold uppercase tracking-wide">Honeypot Intelligence</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                Manage low-interaction and medium-interaction decoys (HTTP web portals, Cowrie SSH terminals, API stubs) with heartbeat tracking and cryptographic payload validation.
              </p>
            </div>

            {/* Capability 2 */}
            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.02] hover:border-[#FB3640]/50 transition-all space-y-3">
              <div className="w-10 h-10 rounded-lg border border-[#FB3640]/40 flex items-center justify-center font-bold text-sm bg-[#FB3640]/10">
                02
              </div>
              <h3 className="text-sm font-bold uppercase tracking-wide">Threat Event Monitoring</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                High-throughput telemetry ingestion pipeline normalizes disparate decoy logs into standard RFC-compliant security event records with strict schema validation.
              </p>
            </div>

            {/* Capability 3 */}
            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.02] hover:border-[#FB3640]/50 transition-all space-y-3">
              <div className="w-10 h-10 rounded-lg border border-[#FB3640]/40 flex items-center justify-center font-bold text-sm bg-[#FB3640]/10">
                03
              </div>
              <h3 className="text-sm font-bold uppercase tracking-wide">Session Correlation</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                Contextual association engine tracks visitor timelines across multiple requests, matching IP recurrence, connection identifiers, and protocol sequences.
              </p>
            </div>

            {/* Capability 4 */}
            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.02] hover:border-[#FB3640]/50 transition-all space-y-3">
              <div className="w-10 h-10 rounded-lg border border-[#FB3640]/40 flex items-center justify-center font-bold text-sm bg-[#FB3640]/10">
                04
              </div>
              <h3 className="text-sm font-bold uppercase tracking-wide">MITRE ATT&CK Mapping</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                Interactive ATT&CK v14.1 Enterprise Matrix Navigator with evidence-supported mapping confidence, analyst review workflows, and technique explorer.
              </p>
            </div>

            {/* Capability 5 */}
            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.02] hover:border-[#FB3640]/50 transition-all space-y-3">
              <div className="w-10 h-10 rounded-lg border border-[#FB3640]/40 flex items-center justify-center font-bold text-sm bg-[#FB3640]/10">
                05
              </div>
              <h3 className="text-sm font-bold uppercase tracking-wide">Evidence Management</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                Cryptographically verifiable evidence preservation with legal hold enforcement, tamper-evident audit trails, and forensic JSON exports.
              </p>
            </div>

            {/* Capability 6 */}
            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.02] hover:border-[#FB3640]/50 transition-all space-y-3">
              <div className="w-10 h-10 rounded-lg border border-[#FB3640]/40 flex items-center justify-center font-bold text-sm bg-[#FB3640]/10">
                06
              </div>
              <h3 className="text-sm font-bold uppercase tracking-wide">Security Investigations</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                Campaign cluster grouping clusters related intrusion attempts by behavioral similarity, tactic sequences, and recurrence fingerprints.
              </p>
            </div>

            {/* Capability 7 */}
            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.02] hover:border-[#FB3640]/50 transition-all space-y-3">
              <div className="w-10 h-10 rounded-lg border border-[#FB3640]/40 flex items-center justify-center font-bold text-sm bg-[#FB3640]/10">
                07
              </div>
              <h3 className="text-sm font-bold uppercase tracking-wide">Threat Analytics</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                Longitudinal time-bucketed aggregation of alert severity distributions, detection rule hit frequencies, and threat actor dwell times.
              </p>
            </div>

            {/* Capability 8 */}
            <div className="p-6 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.02] hover:border-[#FB3640]/50 transition-all space-y-3">
              <div className="w-10 h-10 rounded-lg border border-[#FB3640]/40 flex items-center justify-center font-bold text-sm bg-[#FB3640]/10">
                08
              </div>
              <h3 className="text-sm font-bold uppercase tracking-wide">SOC Operations Dashboard</h3>
              <p className="text-xs text-[#FB3640]/70 leading-relaxed">
                Central command console combining real-time Server-Sent Events (SSE) telemetry, alert triage queues, and one-click incident remediation playbooks.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* 5. HOW IT WORKS (8-Step Workflow Pipeline) */}
      {/* ==================================================================== */}
      <section id="workflow" className="py-24 border-t border-[#FB3640]/15 bg-[#FB3640]/[0.01]">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center max-w-2xl mx-auto space-y-3">
            <div className="text-xs font-mono uppercase tracking-widest text-[#FB3640]/70">
              // OPERATIONAL PIPELINE
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold uppercase tracking-tight">
              From Probing To Intelligence In 8 Steps
            </h2>
            <p className="text-xs sm:text-sm text-[#FB3640]/70 font-mono">
              Deterministic deception lifecycle transforming raw attacker probes into hardened threat telemetry.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-16 font-mono text-xs">
            {[
              { step: '01', title: 'Deploy Sensors', desc: 'Provision isolated deception nodes mimicking sensitive endpoints.' },
              { step: '02', title: 'Capture Interactions', desc: 'Trap adversary port probes, directory traversals, and brute force requests.' },
              { step: '03', title: 'Normalize Telemetry', desc: 'Ingestion pipeline parses payloads into standardized JSON security schemas.' },
              { step: '04', title: 'Detect Behaviour', desc: 'Deterministic correlation policies evaluate threshold and anomaly rules.' },
              { step: '05', title: 'Correlate Sessions', desc: 'Stitch multi-protocol probes from origin IPs into coherent session storylines.' },
              { step: '06', title: 'Map to ATT&CK', desc: 'Associate validated evidence to Enterprise ATT&CK techniques with confidence scores.' },
              { step: '07', title: 'Investigate Evidence', desc: 'SOC analysts triage alerts, review audit notes, and place legal retention holds.' },
              { step: '08', title: 'Visualize Intel', desc: 'Real-time dashboard displays operational coverage, heatmaps, and executive metrics.' },
            ].map((st) => (
              <div key={st.step} className="p-5 rounded-xl border border-[#FB3640]/20 bg-[#000F08] space-y-2">
                <div className="text-lg font-black text-[#FB3640]">{st.step}</div>
                <div className="font-bold uppercase tracking-wider text-[#FB3640]">{st.title}</div>
                <div className="text-[11px] text-[#FB3640]/70 leading-relaxed">{st.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* 6. MITRE ATT&CK SECTION */}
      {/* ==================================================================== */}
      <section id="mitre" className="py-24 border-t border-[#FB3640]/15">
        <div className="max-w-7xl mx-auto px-6 space-y-12">
          <div className="max-w-3xl space-y-4">
            <div className="text-xs font-mono uppercase tracking-widest text-[#FB3640]/70">
              // THREAT FRAMEWORK INTEGRATION
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold uppercase tracking-tight">
              Evidence-Backed MITRE ATT&CK Alignment
            </h2>
            <p className="text-xs sm:text-sm text-[#FB3640]/80 font-mono leading-relaxed">
              Unlike legacy tools that generate speculative technique mappings without validation, SnareSight requires
              direct, evidential proof before assigning ATT&CK labels. Each mapping includes a calculated confidence score,
              strict categorization rationale, and non-attribution safeguards.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
            <div className="p-5 rounded-xl border border-[#FB3640]/30 bg-[#FB3640]/[0.03] space-y-2">
              <div className="flex justify-between items-center text-[10px] text-[#FB3640]/60">
                <span>TECHNIQUE // T1110</span>
                <span className="font-bold text-[#FB3640]">CREDENTIAL ACCESS</span>
              </div>
              <h4 className="text-sm font-bold text-[#FB3640] uppercase">Brute Force (Password Guessing)</h4>
              <p className="text-[11px] text-[#FB3640]/70 leading-relaxed">
                Triggered upon rapid repeated failed logins against the web decoy authentication portal.
              </p>
              <div className="pt-2 text-[10px] text-[#FB3640]/50 border-t border-[#FB3640]/10 flex justify-between">
                <span>RULE: AUTH-001</span>
                <span>CONFIDENCE: 100% (HIGH)</span>
              </div>
            </div>

            <div className="p-5 rounded-xl border border-[#FB3640]/30 bg-[#FB3640]/[0.03] space-y-2">
              <div className="flex justify-between items-center text-[10px] text-[#FB3640]/60">
                <span>TECHNIQUE // T1087</span>
                <span className="font-bold text-[#FB3640]">DISCOVERY</span>
              </div>
              <h4 className="text-sm font-bold text-[#FB3640] uppercase">Account Discovery</h4>
              <p className="text-[11px] text-[#FB3640]/70 leading-relaxed">
                Identifies systematic enumeration of common administrative usernames across multiple distinct sessions.
              </p>
              <div className="pt-2 text-[10px] text-[#FB3640]/50 border-t border-[#FB3640]/10 flex justify-between">
                <span>RULE: AUTH-003</span>
                <span>CONFIDENCE: 85% (HIGH)</span>
              </div>
            </div>

            <div className="p-5 rounded-xl border border-[#FB3640]/30 bg-[#FB3640]/[0.03] space-y-2">
              <div className="flex justify-between items-center text-[10px] text-[#FB3640]/60">
                <span>TECHNIQUE // T1083</span>
                <span className="font-bold text-[#FB3640]">DISCOVERY</span>
              </div>
              <h4 className="text-sm font-bold text-[#FB3640] uppercase">File & Directory Discovery</h4>
              <p className="text-[11px] text-[#FB3640]/70 leading-relaxed">
                Flags unauthorized requests targeting sensitive paths (e.g., .git/config, /admin, /wp-login.php, /etc/passwd).
              </p>
              <div className="pt-2 text-[10px] text-[#FB3640]/50 border-t border-[#FB3640]/10 flex justify-between">
                <span>RULE: WEB-001</span>
                <span>CONFIDENCE: 90% (HIGH)</span>
              </div>
            </div>
          </div>

          {/* Caveat Box */}
          <div className="p-4 rounded-xl border border-[#FB3640]/30 bg-[#000F08] text-xs font-mono text-[#FB3640]/80 flex items-start gap-3">
            <span className="text-base font-bold">⚠️</span>
            <div className="leading-relaxed">
              <strong className="text-[#FB3640] uppercase">Non-Attribution Notice: </strong>
              SnareSight deception telemetry reflects adversary interaction patterns against isolated decoy infrastructure.
              Technique classifications document observed tradecraft; they do not assert confirmed human actor identity, state sponsorship, or compromise of internal production assets.
            </div>
          </div>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* 7. SOC DASHBOARD PLATFORM PREVIEW */}
      {/* ==================================================================== */}
      <section id="preview" className="py-24 border-t border-[#FB3640]/15 bg-[#FB3640]/[0.01]">
        <div className="max-w-7xl mx-auto px-6 space-y-12">
          <div className="text-center max-w-2xl mx-auto space-y-3">
            <div className="text-xs font-mono uppercase tracking-widest text-[#FB3640]/70">
              // INTERACTIVE SOC PREVIEW
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold uppercase tracking-tight">
              Engineered For Security Operations
            </h2>
            <p className="text-xs sm:text-sm text-[#FB3640]/70 font-mono">
              Designed from the ground up for high-tempo threat analysis and rapid incident response.
            </p>
          </div>

          {/* Realistic Dashboard Preview Container */}
          <div className="rounded-2xl border border-[#FB3640]/30 bg-[#000F08] shadow-[0_0_50px_rgba(251,54,64,0.18)] overflow-hidden font-mono">
            {/* Window titlebar */}
            <div className="px-5 py-3 border-b border-[#FB3640]/20 bg-[#FB3640]/5 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[#FB3640]" />
                <span className="w-2.5 h-2.5 rounded-full bg-[#FB3640]/40" />
                <span className="w-2.5 h-2.5 rounded-full bg-[#FB3640]/20" />
                <span className="ml-2 font-bold text-[#FB3640] tracking-wider text-[11px]">SNARESIGHT SOC // OPERATIONS CONSOLE</span>
              </div>
              <div className="text-[10px] text-[#FB3640]/70">GATEWAY: 127.0.0.1:8000 // STATUS: OPERATIONAL</div>
            </div>

            {/* Dashboard Content Mock */}
            <div className="p-6 space-y-6">
              {/* Metric KPI Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.03]">
                  <div className="text-[10px] text-[#FB3640]/60 uppercase">Total Captured Telemetry</div>
                  <div className="text-2xl font-black text-[#FB3640] mt-1">2,841</div>
                  <div className="text-[9px] text-[#FB3640]/50 mt-0.5">+142 events in past 24h</div>
                </div>
                <div className="p-4 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.03]">
                  <div className="text-[10px] text-[#FB3640]/60 uppercase">Correlated Suspicious Sessions</div>
                  <div className="text-2xl font-black text-[#FB3640] mt-1">48</div>
                  <div className="text-[9px] text-[#FB3640]/50 mt-0.5">18 active adversary streams</div>
                </div>
                <div className="p-4 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.03]">
                  <div className="text-[10px] text-[#FB3640]/60 uppercase">Security Detections Triggered</div>
                  <div className="text-2xl font-black text-[#FB3640] mt-1">12</div>
                  <div className="text-[9px] text-[#FB3640]/50 mt-0.5">AUTH-001 & WEB-001 active</div>
                </div>
                <div className="p-4 rounded-xl border border-[#FB3640]/20 bg-[#FB3640]/[0.03]">
                  <div className="text-[10px] text-[#FB3640]/60 uppercase">Enterprise ATT&CK Coverage</div>
                  <div className="text-2xl font-black text-[#FB3640] mt-1">41.7%</div>
                  <div className="text-[9px] text-[#FB3640]/50 mt-0.5">5 mapped detection rules</div>
                </div>
              </div>

              {/* Event Table Simulation */}
              <div className="border border-[#FB3640]/20 rounded-xl overflow-hidden bg-[#000F08]">
                <div className="px-4 py-2.5 bg-[#FB3640]/5 border-b border-[#FB3640]/20 flex justify-between items-center text-xs">
                  <span className="font-bold text-[#FB3640]">LIVE INTRUSION EVENTS</span>
                  <span className="text-[10px] text-[#FB3640]/60">REAL-TIME STREAM ACTIVE</span>
                </div>
                <div className="divide-y divide-[#FB3640]/10 text-xs">
                  {[
                    { time: '02:45:12', ip: '198.51.100.24', event: 'AUTH_FAILED', decoy: 'WEB-001', sev: 'HIGH', rule: 'AUTH-001' },
                    { time: '02:44:59', ip: '198.51.100.24', event: 'USER_PROBE', decoy: 'WEB-001', sev: 'MEDIUM', rule: 'AUTH-003' },
                    { time: '02:43:21', ip: '203.0.113.88', event: 'PATH_TRAVERSAL', decoy: 'WEB-001', sev: 'HIGH', rule: 'WEB-001' },
                    { time: '02:41:05', ip: '192.0.2.71', event: 'SSH_COMMAND', decoy: 'SSH-001', sev: 'CRITICAL', rule: 'SSH-002' },
                  ].map((row, i) => (
                    <div key={i} className="px-4 py-2.5 flex items-center justify-between hover:bg-[#FB3640]/5 transition-colors">
                      <div className="flex items-center gap-4">
                        <span className="text-[#FB3640]/60 text-[11px]">{row.time}</span>
                        <span className="font-bold text-[#FB3640]">{row.ip}</span>
                        <span className="px-1.5 py-0.5 rounded bg-[#FB3640]/10 text-[10px]">{row.event}</span>
                        <span className="text-[#FB3640]/60 text-[11px]">→ {row.decoy}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-[10px] text-[#FB3640]/70">{row.rule}</span>
                        <span className="px-2 py-0.5 rounded bg-[#FB3640] text-[#000F08] font-bold text-[10px]">
                          {row.sev}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="px-6 py-4 bg-[#FB3640]/5 border-t border-[#FB3640]/20 flex items-center justify-between">
              <span className="text-xs text-[#FB3640]/70">Demonstration Lab contains isolated RFC 5737 loopback scenarios.</span>
              <button
                onClick={() => navigate('/app')}
                className="px-4 py-2 bg-[#FB3640] text-[#000F08] font-bold text-xs uppercase tracking-wider rounded-lg hover:bg-[#FB3640]/90 transition-all shadow-[0_0_15px_rgba(251,54,64,0.3)]"
              >
                Access Full Application →
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* 8. SECURITY & ARCHITECTURE */}
      {/* ==================================================================== */}
      <section id="architecture" className="py-24 border-t border-[#FB3640]/15">
        <div className="max-w-7xl mx-auto px-6 space-y-12">
          <div className="max-w-3xl space-y-4">
            <div className="text-xs font-mono uppercase tracking-widest text-[#FB3640]/70">
              // PRODUCTION ARCHITECTURE
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold uppercase tracking-tight">
              Robust, Observable & Containerized
            </h2>
            <p className="text-xs sm:text-sm text-[#FB3640]/80 font-mono leading-relaxed">
              Engineered with zero third-party cloud dependencies. SnareSight runs locally or in isolated on-premise
              clusters via Docker Compose, guaranteeing complete forensic data sovereignty.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 font-mono text-xs">
            <div className="p-5 rounded-xl border border-[#FB3640]/20 bg-[#000F08] space-y-2">
              <div className="text-sm font-bold uppercase text-[#FB3640]">FastAPI Python Core</div>
              <p className="text-[11px] text-[#FB3640]/70 leading-relaxed">
                Asynchronous event ingestion gateway powered by Starlette and Pydantic v2 with salted bcrypt auth and token blacklisting.
              </p>
            </div>

            <div className="p-5 rounded-xl border border-[#FB3640]/20 bg-[#000F08] space-y-2">
              <div className="text-sm font-bold uppercase text-[#FB3640]">PostgreSQL 16 DB</div>
              <p className="text-[11px] text-[#FB3640]/70 leading-relaxed">
                Relational persistence engine managing 74 relational entities with strict foreign-key integrity and Alembic versioning.
              </p>
            </div>

            <div className="p-5 rounded-xl border border-[#FB3640]/20 bg-[#000F08] space-y-2">
              <div className="text-sm font-bold uppercase text-[#FB3640]">React + TypeScript</div>
              <p className="text-[11px] text-[#FB3640]/70 leading-relaxed">
                Enterprise Single Page Application built with Vite, Tailwind CSS, Lucide icons, and React Error Boundaries.
              </p>
            </div>

            <div className="p-5 rounded-xl border border-[#FB3640]/20 bg-[#000F08] space-y-2">
              <div className="text-sm font-bold uppercase text-[#FB3640]">Nginx Gateway</div>
              <p className="text-[11px] text-[#FB3640]/70 leading-relaxed">
                Reverse proxy container routing API requests with rate limiting, security headers, and Single Page Application fallback.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* 9. FINAL CTA SECTION */}
      {/* ==================================================================== */}
      <section className="py-24 border-t border-[#FB3640]/20 bg-[radial-gradient(ellipse_at_bottom,rgba(251,54,64,0.15),transparent_70%)] text-center">
        <div className="max-w-4xl mx-auto px-6 space-y-6">
          <div className="text-xs font-mono uppercase tracking-widest text-[#FB3640]/70">
            // READY FOR DECEPTION ENGINEERING
          </div>
          <h2 className="text-4xl sm:text-5xl font-black uppercase tracking-tight">
            Make Every Deception Count.
          </h2>
          <p className="text-sm sm:text-base text-[#FB3640]/80 font-mono max-w-xl mx-auto leading-relaxed">
            Turn suspicious interactions into structured security intelligence. Deploy your first sensor in minutes.
          </p>
          <div className="pt-4 flex justify-center gap-4">
            <button
              onClick={() => navigate('/app')}
              className="px-8 py-4 rounded-xl bg-[#FB3640] text-[#000F08] font-mono font-bold text-sm uppercase tracking-wider hover:bg-[#FB3640]/90 shadow-[0_0_30px_rgba(251,54,64,0.4)] transition-all"
            >
              Explore SnareSight →
            </button>
          </div>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* 10. COMPREHENSIVE FOOTER */}
      {/* ==================================================================== */}
      <footer className="border-t border-[#FB3640]/20 bg-[#000F08] py-16 px-6 font-mono text-xs">
        <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="space-y-4">
            <BrandLogo size="md" showWordmark={true} />
            <p className="text-[11px] text-[#FB3640]/70 leading-relaxed">
              Deception-Driven Threat Detection & Security Operations Platform. Capture suspicious interactions and turn honeypot telemetry into actionable intelligence.
            </p>
          </div>

          <div className="space-y-3">
            <div className="text-xs font-bold uppercase tracking-wider text-[#FB3640]">Platform</div>
            <ul className="space-y-2 text-[11px] text-[#FB3640]/70">
              <li><button onClick={() => navigate('/app/overview')} className="hover:text-[#FB3640]">SOC Overview</button></li>
              <li><button onClick={() => navigate('/app/events')} className="hover:text-[#FB3640]">Event Monitoring</button></li>
              <li><button onClick={() => navigate('/app/mitre')} className="hover:text-[#FB3640]">MITRE ATT&CK Matrix</button></li>
              <li><button onClick={() => navigate('/app/sensors')} className="hover:text-[#FB3640]">Honeypot Sensors</button></li>
              <li><button onClick={() => navigate('/app/demo')} className="hover:text-[#FB3640]">Demonstration Lab</button></li>
            </ul>
          </div>

          <div className="space-y-3">
            <div className="text-xs font-bold uppercase tracking-wider text-[#FB3640]">Documentation</div>
            <ul className="space-y-2 text-[11px] text-[#FB3640]/70">
              <li><a href="/api/v1/health" target="_blank" rel="noreferrer" className="hover:text-[#FB3640]">System Health Check ↗</a></li>
              <li><a href="http://127.0.0.1:8000/docs" target="_blank" rel="noreferrer" className="hover:text-[#FB3640]">Interactive API Docs ↗</a></li>
              <li><button onClick={() => scrollTo('mitre')} className="hover:text-[#FB3640]">MITRE Technique Mapping</button></li>
              <li><button onClick={() => scrollTo('architecture')} className="hover:text-[#FB3640]">Docker Architecture</button></li>
            </ul>
          </div>

          <div className="space-y-3">
            <div className="text-xs font-bold uppercase tracking-wider text-[#FB3640]">Security & Privacy</div>
            <p className="text-[11px] text-[#FB3640]/70 leading-relaxed">
              Operates exclusively with isolated loopback decoys and non-production telemetry. Zero credential harvesting.
            </p>
            <button
              onClick={() => setPrivacyModalOpen(true)}
              className="text-[11px] underline text-[#FB3640] hover:text-[#FB3640]/80"
            >
              Privacy & Non-Attribution Policy
            </button>
          </div>
        </div>

        <div className="max-w-7xl mx-auto pt-12 mt-12 border-t border-[#FB3640]/15 flex flex-col md:flex-row items-center justify-between gap-4 text-[10px] text-[#FB3640]/60">
          <div>
            © 2026 SnareSight Development Team. All rights reserved.
          </div>
          <div className="flex items-center gap-6">
            <span>Primary Background: #000F08</span>
            <span>Primary Accent: #FB3640</span>
            <span>Strict Binary Palette</span>
          </div>
        </div>
      </footer>

      {/* Privacy & Non-Attribution Modal */}
      {privacyModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#000F08]/80 backdrop-blur-sm">
          <div className="bg-[#000F08] border border-[#FB3640]/40 rounded-2xl max-w-lg w-full p-6 space-y-4 font-mono text-xs shadow-2xl">
            <div className="flex justify-between items-center pb-2 border-b border-[#FB3640]/20">
              <span className="font-bold text-[#FB3640] uppercase">Privacy & Non-Attribution Policy</span>
              <button onClick={() => setPrivacyModalOpen(false)} className="text-[#FB3640] hover:opacity-70">✕</button>
            </div>
            <p className="text-[#FB3640]/80 leading-relaxed">
              SnareSight strictly handles deception telemetry from designated synthetic and isolated decoy assets.
              No personally identifiable information (PII), plain-text production passwords, or unauthorized private host data
              is collected, ingested, or processed.
            </p>
            <p className="text-[#FB3640]/80 leading-relaxed">
              ATT&CK classifications are technical observations of behavior and procedural patterns. They do not constitute
              legal attribution, government affiliation, or physical identity verification.
            </p>
            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setPrivacyModalOpen(false)}
                className="px-4 py-2 bg-[#FB3640] text-[#000F08] font-bold rounded-lg hover:bg-[#FB3640]/90"
              >
                Understood
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LandingPage;

