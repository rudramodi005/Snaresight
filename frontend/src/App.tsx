import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, useLocation, Navigate, useNavigate } from 'react-router-dom';
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
import { SettingsPage } from './features/settings/SettingsPage';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { AuthProvider, useAuth } from './features/auth/AuthContext';
import { LoginPage } from './features/auth/LoginPage';
import { ChangePasswordModal } from './features/auth/ChangePasswordModal';
import { LandingPage } from './features/landing/LandingPage';
import { BrandLogo } from './components/common/BrandLogo';

interface NavSection {
  title: string;
  items: {
    path: string;
    label: string;
    icon: string;
    enabled: boolean;
  }[];
}

const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, isAuthenticated, logout, role } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [globalSearchOpen, setGlobalSearchOpen] = useState(false);
  const [changePasswordOpen, setChangePasswordOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searching, setSearching] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
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

  const navSections: NavSection[] = [
    {
      title: 'OVERVIEW',
      items: [
        { path: '/app/overview', label: 'Operations Overview', icon: '📊', enabled: true },
      ],
    },
    {
      title: 'DETECTION',
      items: [
        { path: '/app/alerts', label: 'Alert Management', icon: '🚨', enabled: true },
        { path: '/app/events', label: 'Security Events', icon: '🛡️', enabled: true },
        { path: '/app/sensors', label: 'Honeypot Sensors', icon: '🪤', enabled: true },
      ],
    },
    {
      title: 'INTELLIGENCE',
      items: [
        { path: '/app/source-intelligence', label: 'Source Intelligence', icon: '🎯', enabled: true },
        { path: '/app/mitre', label: 'MITRE ATT&CK Matrix', icon: '🗺️', enabled: true },
        { path: '/app/mitre/mappings', label: 'Detection Mappings', icon: '📑', enabled: true },
      ],
    },
    {
      title: 'INVESTIGATION',
      items: [
        { path: '/app/investigations', label: 'Campaign Investigations', icon: '📁', enabled: true },
        { path: '/app/sessions', label: 'Session Explorer', icon: '⏱️', enabled: true },
        { path: '/app/sequences', label: 'Attack Chains', icon: '🔗', enabled: true },
      ],
    },
    {
      title: 'RESPONSE & ANALYTICS',
      items: [
        { path: '/app/response', label: 'Defensive Response', icon: '⚡', enabled: true },
        { path: '/app/analytics', label: 'Security Analytics', icon: '📈', enabled: true },
      ],
    },
    {
      title: 'SYSTEM & EVALUATION',
      items: [
        { path: '/app/health', label: 'Platform Health', icon: '🩺', enabled: true },
        { path: '/app/demo', label: 'Demonstration Lab', icon: '🧪', enabled: true },
        { path: '/app/settings', label: 'Settings', icon: '⚙️', enabled: true },
      ],
    },
  ];

  return (
    <div className="flex h-screen bg-[#000F08] text-[#FB3640] overflow-hidden font-sans selection:bg-[#FB3640] selection:text-[#000F08]">
      {/* Mobile Drawer Backdrop */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 bg-[#000F08]/80 backdrop-blur-sm z-30 md:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* 1. Left Sidebar (responsive drawer on mobile, static on desktop) */}
      <aside
        className={`fixed md:static inset-y-0 left-0 w-64 bg-[#000F08] border-r border-[#FB3640]/20 flex flex-col justify-between shrink-0 z-40 transition-transform duration-300 ease-in-out ${
          mobileMenuOpen ? 'translate-x-0 shadow-crimson-lg' : '-translate-x-full md:translate-x-0'
        }`}
      >
        <div className="flex flex-col h-[calc(100vh-140px)]">
          {/* Logo / Brand Header */}
          <div className="h-16 flex items-center justify-between px-4 border-b border-[#FB3640]/20 shrink-0">
            <div className="flex items-center gap-2.5">
              <BrandLogo size={26} showWordmark={false} />
              <div>
                <div className="font-black text-sm tracking-widest text-[#FB3640]">SNARESIGHT</div>
                <div className="text-[9px] uppercase font-mono text-[#FB3640]/70 font-bold tracking-wider">
                  DECEPTION SOAR
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1.5">
              <a
                href="/"
                title="Public Site"
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#FB3640]/10 hover:bg-[#FB3640]/20 text-[#FB3640] border border-[#FB3640]/30 transition-colors"
              >
                Public ↗
              </a>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="md:hidden w-6 h-6 rounded flex items-center justify-center text-xs text-[#FB3640]/70 hover:text-[#FB3640]"
                aria-label="Close menu"
              >
                ✕
              </button>
            </div>
          </div>

          {/* Navigation Links Grouped by Section */}
          <nav className="p-3 space-y-4 overflow-y-auto flex-1">
            {navSections.map((sec) => (
              <div key={sec.title} className="space-y-1">
                <div className="text-[9px] font-mono font-bold uppercase tracking-wider text-[#FB3640]/40 px-2.5 py-0.5">
                  {sec.title}
                </div>
                {sec.items.map((item) => {
                  const isActive = location.pathname === item.path;
                  return (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      onClick={() => setMobileMenuOpen(false)}
                      className={`flex items-center gap-2.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
                        isActive
                          ? 'bg-[#FB3640] text-[#000F08] font-black shadow-crimson-sm'
                          : 'text-[#FB3640]/75 hover:text-[#FB3640] hover:bg-[#FB3640]/10'
                      }`}
                    >
                      <span className="text-sm">{item.icon}</span>
                      <span>{item.label}</span>
                    </NavLink>
                  );
                })}
              </div>
            ))}
          </nav>
        </div>

        {/* User Info / Profile footer */}
        <div className="p-3 border-t border-[#FB3640]/20 bg-[#000F08] shrink-0">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <div className="w-7 h-7 rounded-lg bg-[#FB3640] flex items-center justify-center font-black text-xs text-[#000F08] shrink-0">
                {user?.username ? user.username.substring(0, 2).toUpperCase() : 'SO'}
              </div>
              <div className="overflow-hidden">
                <div className="text-xs font-bold text-[#FB3640] truncate">
                  {user?.username || 'soc_lead'}
                </div>
                <div className="text-[10px] text-[#FB3640]/60 truncate font-mono">
                  {user?.full_name || 'SOC Analyst'}
                </div>
              </div>
            </div>
            <span className="text-[9px] font-mono font-bold px-2 py-0.5 rounded border border-[#FB3640]/40 text-[#FB3640] bg-[#FB3640]/10 uppercase shrink-0">
              {role}
            </span>
          </div>

          <div className="flex items-center gap-1.5 pt-1">
            <button
              onClick={() => {
                setMobileMenuOpen(false);
                setChangePasswordOpen(true);
              }}
              className="flex-1 py-1 px-2 rounded-lg bg-[#000F08] hover:bg-[#FB3640]/10 text-[10px] font-semibold text-[#FB3640] border border-[#FB3640]/30 transition-colors text-center"
              title="Change Password"
            >
              🔒 Password
            </button>
            <button
              onClick={() => {
                logout();
                navigate('/login');
              }}
              className="py-1 px-3 rounded-lg bg-[#000F08] hover:bg-[#FB3640]/20 text-[10px] font-semibold text-[#FB3640] border border-[#FB3640]/30 hover:border-[#FB3640] transition-colors"
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
        <header className="h-16 bg-[#000F08] border-b border-[#FB3640]/20 flex items-center justify-between px-4 md:px-6 shrink-0 z-20 gap-3">
          <div className="flex items-center gap-3 flex-1 max-w-xl">
            {/* Mobile Hamburger Toggle Button */}
            <button
              type="button"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden w-9 h-9 rounded-xl bg-[#000F08] border border-[#FB3640]/30 hover:border-[#FB3640] flex items-center justify-center text-sm text-[#FB3640] shrink-0 transition-colors"
              aria-label="Toggle navigation drawer"
            >
              ☰
            </button>

            {/* Global Search trigger */}
            <div className="w-full">
              <button
                onClick={() => setGlobalSearchOpen(true)}
                className="w-full bg-[#000F08] border border-[#FB3640]/30 hover:border-[#FB3640] rounded-xl px-3.5 py-2 text-xs text-[#FB3640]/70 flex items-center justify-between transition-colors font-mono"
              >
                <span className="flex items-center gap-2 truncate">
                  <span>🔍</span> <span className="truncate">Search events, sessions, IPs, alerts...</span>
                </span>
                <kbd className="hidden sm:inline-block px-1.5 py-0.5 bg-[#FB3640]/10 border border-[#FB3640]/30 rounded text-[10px] font-mono text-[#FB3640] shrink-0">
                  Ctrl+K
                </kbd>
              </button>
            </div>
          </div>

          {/* Right Header Status Controls */}
          <div className="flex items-center gap-2 sm:gap-4 shrink-0">
            {/* Live SSE Connection Indicator */}
            <div className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-3 py-1 rounded-full bg-[#000F08] border border-[#FB3640]/30 text-xs">
              <span className="w-2 h-2 rounded-full bg-[#FB3640] animate-pulse shrink-0" />
              <span className="text-[10px] sm:text-[11px] font-mono font-bold text-[#FB3640] whitespace-nowrap">
                <span className="hidden sm:inline">SSE: </span>CONNECTED
              </span>
            </div>

            {/* Notifications Button */}
            <div className="relative">
              <button
                onClick={() => setNotificationsOpen(!notificationsOpen)}
                className="w-9 h-9 rounded-xl bg-[#000F08] border border-[#FB3640]/30 hover:border-[#FB3640] flex items-center justify-center text-sm text-[#FB3640] transition-colors"
              >
                🔔
              </button>

              {notificationsOpen && (
                <div className="absolute right-0 mt-2 w-80 bg-[#000F08] border border-[#FB3640]/30 rounded-2xl shadow-crimson-lg p-4 text-xs z-50 glass-panel">
                  <div className="flex justify-between items-center mb-3 pb-2 border-b border-[#FB3640]/20">
                    <span className="font-bold text-[#FB3640]">System Notifications</span>
                    <button
                      onClick={() => setNotificationsOpen(false)}
                      className="text-[#FB3640]/70 hover:text-[#FB3640]"
                    >
                      ✕
                    </button>
                  </div>
                  <div className="space-y-2 text-[#FB3640]/80 py-1">
                    <div className="p-2.5 bg-[#000F08] rounded-xl border border-[#FB3640]/20">
                      <div className="text-[#FB3640] font-bold text-[11px] flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#FB3640]" />
                        Pipeline Operational
                      </div>
                      <div className="text-[10px] text-[#FB3640]/70 mt-1">
                        Ingestion, normalization, and ATT&CK mapping running normally.
                      </div>
                    </div>
                    <div className="p-2.5 bg-[#000F08] rounded-xl border border-[#FB3640]/20">
                      <div className="text-[#FB3640] font-bold text-[11px] flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#FB3640]" />
                        Decoy Telemetry Live
                      </div>
                      <div className="text-[10px] text-[#FB3640]/70 mt-1">
                        Sensors WEB-001 and SSH-001 actively receiving interaction events.
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Global Search Modal */}
        {globalSearchOpen && (
          <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-[#000F08]/80 backdrop-blur-md p-4">
            <div className="bg-[#000F08] border border-[#FB3640]/30 rounded-2xl w-full max-w-2xl shadow-crimson-lg overflow-hidden glass-panel">
              <div className="p-3.5 border-b border-[#FB3640]/20 flex items-center gap-3">
                <span className="text-[#FB3640]">🔍</span>
                <input
                  type="text"
                  autoFocus
                  placeholder="Type to search events, sessions, source IPs, alerts, or investigations..."
                  value={searchQuery}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="w-full bg-transparent text-sm text-[#FB3640] placeholder-[#FB3640]/40 focus:outline-none font-mono"
                />
                <button
                  onClick={() => {
                    setGlobalSearchOpen(false);
                    setSearchQuery('');
                    setSearchResults([]);
                  }}
                  className="text-xs font-mono text-[#FB3640]/60 hover:text-[#FB3640] px-2 py-1 rounded border border-[#FB3640]/20"
                >
                  ESC
                </button>
              </div>

              <div className="max-h-96 overflow-y-auto p-3 text-xs">
                {searching ? (
                  <div className="py-8 text-center text-[#FB3640]/60 font-mono">Searching platform index...</div>
                ) : searchResults.length === 0 ? (
                  <div className="py-8 text-center text-[#FB3640]/60 font-mono">
                    {searchQuery.trim().length < 2
                      ? 'Type at least 2 characters to search across platform entities.'
                      : 'No matching records found in platform index.'}
                  </div>
                ) : (
                  <div className="space-y-2">
                    {searchResults.map((item, idx) => (
                      <a
                        key={idx}
                        href={item.navigation_url}
                        onClick={() => setGlobalSearchOpen(false)}
                        className="block p-3 rounded-xl bg-[#000F08] hover:bg-[#FB3640]/10 border border-[#FB3640]/20 hover:border-[#FB3640]/40 transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-[#FB3640]">{item.title}</span>
                          <span className="text-[10px] uppercase font-mono font-bold text-[#FB3640] bg-[#FB3640]/15 px-2 py-0.5 rounded border border-[#FB3640]/30">
                            {item.categoryName}
                          </span>
                        </div>
                        <div className="text-[#FB3640]/70 mt-1 text-[11px] font-mono">{item.subtitle}</div>
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
          <ErrorBoundary>
            {children}
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public Landing Page */}
          <Route path="/" element={<LandingPage />} />

          {/* Authentication Route */}
          <Route path="/login" element={<LoginPage />} />

          {/* Authenticated Application Routes under /app */}
          <Route
            path="/app"
            element={
              <AppShell>
                <Navigate to="/app/overview" replace />
              </AppShell>
            }
          />
          <Route
            path="/app/overview"
            element={
              <AppShell>
                <SecurityOperationsOverviewPage />
              </AppShell>
            }
          />
          <Route
            path="/app/alerts"
            element={
              <AppShell>
                <AlertManagementPage />
              </AppShell>
            }
          />
          <Route
            path="/app/events"
            element={
              <AppShell>
                <SecurityEventsPage />
              </AppShell>
            }
          />
          <Route
            path="/app/investigations"
            element={
              <AppShell>
                <CampaignInvestigationsPage />
              </AppShell>
            }
          />
          <Route
            path="/app/source-intelligence"
            element={
              <AppShell>
                <SourceIntelligencePage />
              </AppShell>
            }
          />
          <Route
            path="/app/sessions"
            element={
              <AppShell>
                <SessionInvestigationPage />
              </AppShell>
            }
          />
          <Route
            path="/app/sequences"
            element={
              <AppShell>
                <SequenceInvestigationPage />
              </AppShell>
            }
          />
          <Route
            path="/app/mitre"
            element={
              <AppShell>
                <MitreAttackDashboardPage />
              </AppShell>
            }
          />
          <Route
            path="/app/mitre/mappings"
            element={
              <AppShell>
                <MitreMappingsPage />
              </AppShell>
            }
          />
          <Route
            path="/app/analytics"
            element={
              <AppShell>
                <SecurityAnalyticsPage />
              </AppShell>
            }
          />
          <Route
            path="/app/response"
            element={
              <AppShell>
                <DefensiveResponseCenterPage />
              </AppShell>
            }
          />
          <Route
            path="/app/sensors"
            element={
              <AppShell>
                <SensorOperationsPage />
              </AppShell>
            }
          />
          <Route
            path="/app/health"
            element={
              <AppShell>
                <PlatformSecurityHealthPage />
              </AppShell>
            }
          />
          <Route
            path="/app/demo"
            element={
              <AppShell>
                <DemonstrationControlPage />
              </AppShell>
            }
          />
          <Route
            path="/app/settings"
            element={
              <AppShell>
                <SettingsPage />
              </AppShell>
            }
          />

          {/* Legacy flat route redirects for seamless compatibility */}
          <Route path="/overview" element={<Navigate to="/app/overview" replace />} />
          <Route path="/alerts" element={<Navigate to="/app/alerts" replace />} />
          <Route path="/events" element={<Navigate to="/app/events" replace />} />
          <Route path="/investigations" element={<Navigate to="/app/investigations" replace />} />
          <Route path="/source-intelligence" element={<Navigate to="/app/source-intelligence" replace />} />
          <Route path="/sessions" element={<Navigate to="/app/sessions" replace />} />
          <Route path="/sequences" element={<Navigate to="/app/sequences" replace />} />
          <Route path="/mitre" element={<Navigate to="/app/mitre" replace />} />
          <Route path="/mitre/mappings" element={<Navigate to="/app/mitre/mappings" replace />} />
          <Route path="/analytics" element={<Navigate to="/app/analytics" replace />} />
          <Route path="/response" element={<Navigate to="/app/response" replace />} />
          <Route path="/sensors" element={<Navigate to="/app/sensors" replace />} />
          <Route path="/health" element={<Navigate to="/app/health" replace />} />
          <Route path="/demo" element={<Navigate to="/app/demo" replace />} />
          <Route path="/settings" element={<Navigate to="/app/settings" replace />} />

          {/* Fallback to Public Landing Page */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default App;
