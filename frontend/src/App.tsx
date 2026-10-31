import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import SecurityOperationsOverviewPage from './features/dashboard/SecurityOperationsOverviewPage';
import SecurityEventsPage from './features/events/SecurityEventsPage';
import { AlertManagementPage } from './features/alerts/AlertManagementPage';
import { CampaignInvestigationsPage } from './features/campaigns/CampaignInvestigationsPage';
import { SourceIntelligencePage } from './features/source-intelligence/SourceIntelligencePage';
import { SessionInvestigationPage } from './features/sessions/SessionInvestigationPage';
import { SequenceInvestigationPage } from './features/sequences/SequenceInvestigationPage';
import { MitreAttackDashboardPage } from './features/mitre/MitreAttackDashboardPage';
import { MitreMappingsPage } from './features/mitre/MitreMappingsPage';
import { SecurityAnalyticsPage } from './features/analytics/SecurityAnalyticsPage';
import { DefensiveResponseCenterPage } from './features/response/DefensiveResponseCenterPage';
import { SensorOperationsPage } from './features/sensors/SensorOperationsPage';
import { PlatformSecurityHealthPage } from './features/resilience/PlatformSecurityHealthPage';
import { DemonstrationControlPage } from './features/demo/DemonstrationControlPage';
import { AuthProvider, useAuth } from './features/auth/AuthContext';
import { LoginPage } from './features/auth/LoginPage';
import { ChangePasswordModal } from './features/auth/ChangePasswordModal';

const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, isAuthenticated, logout, role } = useAuth();
  const [globalSearchOpen, setGlobalSearchOpen] = useState(false);
  const [changePasswordOpen, setChangePasswordOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searching, setSearching] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const location = useLocation();

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  const handleSearch = async (q: string) => {
    setSearchQuery(q);
    if (q.trim().length < 2) {
      setSearchResults([]);
      return;
    }
    setSearching(true);
    try {
      const res = await fetch(`/api/v1/dashboard/search?q=${encodeURIComponent(q.trim())}`);
      if (res.ok) {
        const data = await res.json();
        const allItems: any[] = [];
        Object.entries(data.results_by_category || {}).forEach(([cat, items]: [string, any]) => {
          items.forEach((item: any) => allItems.push({ ...item, categoryName: cat }));
        });
        setSearchResults(allItems);
      }
    } catch (err) {
      console.error('Search error:', err);
    } finally {
      setSearching(false);
    }
  };

  const navItems = [
    { path: '/overview', label: 'Overview', icon: '📊', enabled: true },
    { path: '/alerts', label: 'Alert Management', icon: '🚨', enabled: true },
    { path: '/events', label: 'Security Events', icon: '🛡️', enabled: true },
    { path: '/investigations', label: 'Campaign Investigations', icon: '📁', enabled: true },
    { path: '/source-intelligence', label: 'Source Intelligence', icon: '🎯', enabled: true },
    { path: '/sessions', label: 'Session Explorer', icon: '⏱️', enabled: true },
    { path: '/sequences', label: 'Attack Chains', icon: '🔗', enabled: true },
    { path: '/mitre', label: 'MITRE ATT&CK', icon: '🗺️', enabled: true },
    { path: '/analytics', label: 'Security Analytics', icon: '📈', enabled: true },
    { path: '/response', label: 'Defensive Response', icon: '🛡️', enabled: true },
    { path: '/sensors', label: 'Honeypot Sensors', icon: '🪤', enabled: true },
    { path: '/health', label: 'Platform Health', icon: '🩺', enabled: true },
    { path: '/demo', label: 'Demonstration Lab', icon: '🧪', enabled: true },
    { path: '/live-monitoring', label: 'Live Monitoring', icon: '📡', enabled: false },
    { path: '/settings', label: 'Settings', icon: '⚙️', enabled: false },
  ];

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* 1. Left Sidebar */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between shrink-0">
        <div>
          {/* Logo / Brand Header */}
          <div className="h-16 flex items-center gap-3 px-5 border-b border-slate-800">
            <span className="text-2xl">🕸️</span>
            <div>
              <div className="font-bold text-base tracking-wider text-slate-100">SNARESIGHT</div>
              <div className="text-[10px] uppercase font-mono text-emerald-400 font-semibold tracking-wider">
                Deception Platform
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1 overflow-y-auto">
            {navItems.map((item) => {
              if (!item.enabled) {
                return (
                  <div
                    key={item.label}
                    className="flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium text-slate-600 cursor-not-allowed select-none"
                    title="Planned feature"
                  >
                    <div className="flex items-center gap-2.5">
                      <span>{item.icon}</span>
                      <span>{item.label}</span>
                    </div>
                    <span className="text-[9px] uppercase px-1.5 py-0.2 bg-slate-800/80 rounded text-slate-500">
                      Planned
                    </span>
                  </div>
                );
              }

              const isActive =
                location.pathname === item.path ||
                (item.path === '/overview' && location.pathname === '/');

              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <span>{item.icon}</span>
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* User Info / Profile footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/40">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center font-bold text-xs text-white shrink-0">
                {user?.username ? user.username.substring(0, 2).toUpperCase() : 'SOC'}
              </div>
              <div className="overflow-hidden">
                <div className="text-xs font-semibold text-slate-200 truncate">
                  {user?.username || 'soc_lead'}
                </div>
                <div className="text-[10px] text-slate-500 truncate">
                  {user?.full_name || 'SOC Analyst'}
                </div>
              </div>
            </div>
            <span
              className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase shrink-0 ${
                role === 'ADMIN'
                  ? 'bg-amber-950/60 text-amber-400 border-amber-800/80'
                  : role === 'ANALYST'
                  ? 'bg-blue-950/60 text-blue-400 border-blue-800/80'
                  : 'bg-emerald-950/60 text-emerald-400 border-emerald-800/80'
              }`}
            >
              {role}
            </span>
          </div>

          <div className="flex items-center gap-1.5 pt-1">
            <button
              onClick={() => setChangePasswordOpen(true)}
              className="flex-1 py-1 px-2 rounded bg-slate-900 hover:bg-slate-800 text-[10px] text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors text-center"
              title="Change Password"
            >
              🔒 Password
            </button>
            <button
              onClick={() => logout()}
              className="py-1 px-2.5 rounded bg-slate-900 hover:bg-rose-950/60 text-[10px] text-slate-400 hover:text-rose-400 border border-slate-800 hover:border-rose-900 transition-colors"
              title="Sign Out"
            >
              Sign Out
            </button>
          </div>
        </div>
      </aside>

      {/* Change Password Modal */}
      <ChangePasswordModal
        isOpen={changePasswordOpen}
        onClose={() => setChangePasswordOpen(false)}
      />

      {/* 2. Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navigation Bar */}
        <header className="h-16 bg-slate-900 border-b border-slate-800 flex items-center justify-between px-6 shrink-0 z-20">
          {/* Global Search trigger */}
          <div className="w-96">
            <button
              onClick={() => setGlobalSearchOpen(true)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-1.5 text-xs text-slate-400 hover:border-slate-700 flex items-center justify-between transition-colors"
            >
              <span className="flex items-center gap-2">
                <span>🔍</span> Search events, sessions, IPs, or alerts...
              </span>
              <kbd className="px-1.5 py-0.5 bg-slate-800 rounded text-[10px] font-mono text-slate-500">
                Ctrl+K
              </kbd>
            </button>
          </div>

          {/* Right Header Status Controls */}
          <div className="flex items-center gap-4">
            {/* Live SSE Connection Indicator */}
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-950 border border-slate-800 text-xs">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-[11px] font-semibold text-slate-300">SSE: CONNECTED</span>
            </div>

            {/* Notifications Button */}
            <div className="relative">
              <button
                onClick={() => setNotificationsOpen(!notificationsOpen)}
                className="w-8 h-8 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-center text-xs text-slate-300 hover:text-white transition-colors"
              >
                🔔
              </button>

              {notificationsOpen && (
                <div className="absolute right-0 mt-2 w-80 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-4 text-xs z-50">
                  <div className="flex justify-between items-center mb-2 pb-2 border-b border-slate-800">
                    <span className="font-bold text-slate-200">System Notifications</span>
                    <button
                      onClick={() => setNotificationsOpen(false)}
                      className="text-slate-400 hover:text-white"
                    >
                      ✕
                    </button>
                  </div>
                  <div className="space-y-2 text-slate-400 py-1">
                    <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
                      <div className="text-emerald-400 font-semibold text-[11px]">Pipeline Operational</div>
                      <div className="text-[10px] text-slate-400 mt-0.5">Ingestion and normalization running normally.</div>
                    </div>
                    <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
                      <div className="text-blue-400 font-semibold text-[11px]">Decoy Status</div>
                      <div className="text-[10px] text-slate-400 mt-0.5">Sensors WEB-001 and SSH-001 receiving telemetry.</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Global Search Modal */}
        {globalSearchOpen && (
          <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-black/70 backdrop-blur-sm p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-2xl shadow-2xl overflow-hidden">
              <div className="p-3 border-b border-slate-800 flex items-center gap-3">
                <span>🔍</span>
                <input
                  type="text"
                  autoFocus
                  placeholder="Type to search events, sessions, source IPs, alerts, or investigations..."
                  value={searchQuery}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
                />
                <button
                  onClick={() => {
                    setGlobalSearchOpen(false);
                    setSearchQuery('');
                    setSearchResults([]);
                  }}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  ESC
                </button>
              </div>

              <div className="max-h-96 overflow-y-auto p-3 text-xs">
                {searching ? (
                  <div className="py-8 text-center text-slate-500">Searching...</div>
                ) : searchResults.length === 0 ? (
                  <div className="py-8 text-center text-slate-500">
                    {searchQuery.trim().length < 2
                      ? 'Type at least 2 characters to search across platform entities.'
                      : 'No matching records found.'}
                  </div>
                ) : (
                  <div className="space-y-2">
                    {searchResults.map((item, idx) => (
                      <a
                        key={idx}
                        href={item.navigation_url}
                        onClick={() => setGlobalSearchOpen(false)}
                        className="block p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800/80 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-200">{item.title}</span>
                          <span className="text-[10px] uppercase font-bold text-blue-400 bg-blue-950/60 px-1.5 py-0.5 rounded">
                            {item.categoryName}
                          </span>
                        </div>
                        <div className="text-slate-400 mt-0.5 text-[11px]">{item.subtitle}</div>
                      </a>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Page Content View */}
        <main className="flex-1 overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppShell>
          <Routes>
            <Route path="/" element={<SecurityOperationsOverviewPage />} />
            <Route path="/overview" element={<SecurityOperationsOverviewPage />} />
            <Route path="/alerts" element={<AlertManagementPage />} />
            <Route path="/events" element={<SecurityEventsPage />} />
            <Route path="/investigations" element={<CampaignInvestigationsPage />} />
            <Route path="/source-intelligence" element={<SourceIntelligencePage />} />
            <Route path="/sessions" element={<SessionInvestigationPage />} />
            <Route path="/sequences" element={<SequenceInvestigationPage />} />
            <Route path="/mitre" element={<MitreAttackDashboardPage />} />
            <Route path="/mitre/mappings" element={<MitreMappingsPage />} />
            <Route path="/analytics" element={<SecurityAnalyticsPage />} />
            <Route path="/response" element={<DefensiveResponseCenterPage />} />
            <Route path="/sensors" element={<SensorOperationsPage />} />
            <Route path="/health" element={<PlatformSecurityHealthPage />} />
            <Route path="/demo" element={<DemonstrationControlPage />} />
            {/* Fallback to Overview */}
            <Route path="*" element={<SecurityOperationsOverviewPage />} />
          </Routes>
        </AppShell>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;

