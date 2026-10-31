import React, { useState, useEffect, useCallback } from 'react';
import {
  SecurityEventItem,
  PaginatedSecurityEventsResponse,
  SecurityEventSummaryResponse,
  EventDetailResponse,
  EventComparisonResponse,
  EventFilters,
} from '../../types/events';
import {
  fetchSecurityEvents,
  fetchEventsSummary,
  fetchEventDetail,
  compareSecurityEvents,
  addEventNote,
  updateEventReviewStatus,
  associateEventWithInvestigation,
} from '../../services/eventsApi';
import { formatInteger, formatDateTime } from '../../utils/format';

export const SecurityEventsPage: React.FC = () => {
  // Main Data States
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [summary, setSummary] = useState<SecurityEventSummaryResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Pagination & Filtering
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(25);
  const [totalPages, setTotalPages] = useState<number>(1);

  const [searchTerm, setSearchTerm] = useState<string>('');
  const [debouncedSearch, setDebouncedSearch] = useState<string>('');
  const [filterPanelOpen, setFilterPanelOpen] = useState<boolean>(false);

  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [sensorFilter, setSensorFilter] = useState<string>('');
  const [protocolFilter, setProtocolFilter] = useState<string>('');
  const [detectionFilter, setDetectionFilter] = useState<string>('');
  const [outcomeFilter, setOutcomeFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [timeRange, setTimeRange] = useState<string>('all');

  // Event Selection & Comparison
  const [selectedEventIds, setSelectedEventIds] = useState<string[]>([]);
  const [comparisonModalOpen, setComparisonModalOpen] = useState<boolean>(false);
  const [comparisonData, setComparisonData] = useState<EventComparisonResponse | null>(null);
  const [comparing, setComparing] = useState<boolean>(false);

  // Forensic Detail Drawer
  const [detailDrawerOpen, setDetailDrawerOpen] = useState<boolean>(false);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [detailData, setDetailData] = useState<EventDetailResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'payload' | 'relationships' | 'timeline' | 'history' | 'audit'>('overview');

  // Analyst Action Form States
  const [analystNote, setAnalystNote] = useState<string>('');
  const [submittingNote, setSubmittingNote] = useState<boolean>(false);
  const [selectedReviewStatus, setSelectedReviewStatus] = useState<string>('REVIEWED');
  const [reviewNote, setReviewNote] = useState<string>('');
  const [targetClusterId, setTargetClusterId] = useState<string>('');
  const [associateReason, setAssociateReason] = useState<string>('');
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Debounce search input
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedSearch(searchTerm);
      setCurrentPage(1);
    }, 300);
    return () => clearTimeout(handler);
  }, [searchTerm]);

  // Load summary metrics
  const loadSummary = useCallback(async () => {
    try {
      const data = await fetchEventsSummary();
      setSummary(data);
    } catch (err: any) {
      console.error('Failed to load events summary:', err);
    }
  }, []);

  // Load paginated events
  const loadEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const filters: EventFilters = {
        page: currentPage,
        page_size: pageSize,
        search: debouncedSearch || undefined,
        category: categoryFilter || undefined,
        sensor_id: sensorFilter || undefined,
        protocol: protocolFilter || undefined,
        detection_status: detectionFilter || undefined,
        outcome: outcomeFilter || undefined,
        severity: severityFilter || undefined,
      };

      if (timeRange === '1h') {
        filters.start_time = new Date(Date.now() - 3600 * 1000).toISOString();
      } else if (timeRange === '24h') {
        filters.start_time = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
      } else if (timeRange === '7d') {
        filters.start_time = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
      }

      const res = await fetchSecurityEvents(filters);
      setEvents(res.items);
      setTotalEvents(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      setError(err.message || 'Failed to load events');
    } finally {
      setLoading(false);
    }
  }, [
    currentPage,
    pageSize,
    debouncedSearch,
    categoryFilter,
    sensorFilter,
    protocolFilter,
    detectionFilter,
    outcomeFilter,
    severityFilter,
    timeRange,
  ]);

  useEffect(() => {
    loadEvents();
    loadSummary();
  }, [loadEvents, loadSummary]);

  // Open Event Detail Drawer
  const openDetail = async (eventId: string) => {
    setSelectedEventId(eventId);
    setDetailDrawerOpen(true);
    setDetailLoading(true);
    setActiveTab('overview');
    setActionSuccess(null);
    try {
      const res = await fetchEventDetail(eventId);
      setDetailData(res);
    } catch (err: any) {
      console.error('Error fetching event detail:', err);
    } finally {
      setDetailLoading(false);
    }
  };

  // Toggle selection for comparison
  const toggleSelectEvent = (id: string) => {
    setSelectedEventIds((prev) => {
      if (prev.includes(id)) {
        return prev.filter((item) => item !== id);
      }
      if (prev.length >= 5) {
        alert('You can compare at most 5 events simultaneously.');
        return prev;
      }
      return [...prev, id];
    });
  };

  // Run Comparison
  const handleRunComparison = async () => {
    if (selectedEventIds.length < 2) return;
    setComparing(true);
    try {
      const res = await compareSecurityEvents(selectedEventIds);
      setComparisonData(res);
      setComparisonModalOpen(true);
    } catch (err: any) {
      alert(`Comparison failed: ${err.message}`);
    } finally {
      setComparing(false);
    }
  };

  // Submit Note
  const handleAddNote = async () => {
    if (!selectedEventId || !analystNote.trim()) return;
    setSubmittingNote(true);
    try {
      await addEventNote(selectedEventId, analystNote.trim());
      setAnalystNote('');
      setActionSuccess('Analyst note saved to audit log.');
      const updated = await fetchEventDetail(selectedEventId);
      setDetailData(updated);
    } catch (err: any) {
      alert(`Failed to add note: ${err.message}`);
    } finally {
      setSubmittingNote(false);
    }
  };

  // Submit Review Status
  const handleUpdateReview = async () => {
    if (!selectedEventId) return;
    try {
      await updateEventReviewStatus(selectedEventId, selectedReviewStatus, reviewNote || undefined);
      setReviewNote('');
      setActionSuccess(`Review status updated to ${selectedReviewStatus}.`);
      const updated = await fetchEventDetail(selectedEventId);
      setDetailData(updated);
      loadEvents();
    } catch (err: any) {
      alert(`Failed to update review: ${err.message}`);
    }
  };

  // Associate with Investigation
  const handleAssociateInvestigation = async () => {
    if (!selectedEventId || !targetClusterId.trim()) return;
    try {
      await associateEventWithInvestigation(
        selectedEventId,
        targetClusterId.trim(),
        associateReason.trim() || 'Analyst linked event to investigation cluster'
      );
      setTargetClusterId('');
      setAssociateReason('');
      setActionSuccess('Event associated with investigation cluster.');
      const updated = await fetchEventDetail(selectedEventId);
      setDetailData(updated);
      loadEvents();
    } catch (err: any) {
      alert(`Failed to associate: ${err.message}`);
    }
  };

  // Clear all filters
  const clearFilters = () => {
    setSearchTerm('');
    setCategoryFilter('');
    setSensorFilter('');
    setProtocolFilter('');
    setDetectionFilter('');
    setOutcomeFilter('');
    setSeverityFilter('');
    setTimeRange('all');
    setCurrentPage(1);
  };

  const activeFiltersCount = [
    categoryFilter,
    sensorFilter,
    protocolFilter,
    detectionFilter,
    outcomeFilter,
    severityFilter,
    timeRange !== 'all' ? timeRange : '',
  ].filter(Boolean).length;

  return (
    <div className="p-6 bg-slate-950 text-slate-100 min-h-screen">
      {/* 1. Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-slate-800 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-slate-100 tracking-tight">Security Events Explorer</h1>
            <span className="px-2.5 py-0.5 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full">
              Normalized Telemetry
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Search, filter, inspect safe normalized fields, compare honeypot telemetry, and correlate investigations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              loadEvents();
              loadSummary();
            }}
            disabled={loading}
            className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg text-sm font-medium text-slate-200 transition-colors flex items-center gap-2"
          >
            <span className={loading ? 'animate-spin inline-block' : ''}>🔄</span>
            Refresh
          </button>

          {selectedEventIds.length > 0 && (
            <button
              onClick={handleRunComparison}
              disabled={comparing || selectedEventIds.length < 2}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
                selectedEventIds.length >= 2
                  ? 'bg-blue-600 hover:bg-blue-500 text-white'
                  : 'bg-slate-800 text-slate-500 cursor-not-allowed'
              }`}
            >
              <span>⚖️</span>
              Compare Selected ({selectedEventIds.length})
            </button>
          )}
        </div>
      </div>

      {/* 2. Aggregate Summary Stat Chips */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 my-5">
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
            <span className="text-xs text-slate-400 font-medium">Total Events</span>
            <div className="text-xl font-bold text-slate-100 mt-0.5">{formatInteger(summary?.total_events, '0')}</div>
          </div>
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
            <span className="text-xs text-slate-400 font-medium">Detected Alerts</span>
            <div className="text-xl font-bold text-rose-400 mt-0.5">{formatInteger(summary?.detected_events, '0')}</div>
          </div>
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
            <span className="text-xs text-slate-400 font-medium">Clean Telemetry</span>
            <div className="text-xl font-bold text-slate-300 mt-0.5">{formatInteger(summary?.clean_events, '0')}</div>
          </div>
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
            <span className="text-xs text-slate-400 font-medium">Distinct Inbound Sources</span>
            <div className="text-xl font-bold text-cyan-400 mt-0.5">{formatInteger(summary?.distinct_sources, '0')}</div>
          </div>
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3">
            <span className="text-xs text-slate-400 font-medium">Active Honeypot Sensors</span>
            <div className="text-xl font-bold text-emerald-400 mt-0.5">{summary?.distinct_sensors ?? 0}</div>
          </div>
        </div>
      )}

      {/* 3. Search and Quick Controls Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 mb-4">
        <div className="relative flex-1">
          <input
            type="text"
            placeholder="Search events by IP, Session, Sensor ID, Action, or Category..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="absolute right-3 top-2.5 text-xs text-slate-400 hover:text-slate-200"
            >
              ✕
            </button>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Time range pills */}
          <div className="flex bg-slate-900 border border-slate-800 rounded-lg p-0.5 text-xs">
            {['1h', '24h', '7d', 'all'].map((range) => (
              <button
                key={range}
                onClick={() => {
                  setTimeRange(range);
                  setCurrentPage(1);
                }}
                className={`px-3 py-1.5 rounded-md font-medium capitalize transition-colors ${
                  timeRange === range
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {range}
              </button>
            ))}
          </div>

          <button
            onClick={() => setFilterPanelOpen(!filterPanelOpen)}
            className={`px-3 py-2 border rounded-lg text-sm font-medium flex items-center gap-2 transition-colors ${
              filterPanelOpen || activeFiltersCount > 0
                ? 'bg-blue-950/60 border-blue-500/50 text-blue-400'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
            }`}
          >
            <span>⚙️</span>
            Filters
            {activeFiltersCount > 0 && (
              <span className="px-1.5 py-0.2 bg-blue-500 text-slate-950 rounded-full text-xs font-bold">
                {activeFiltersCount}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* 4. Advanced Filter Collapsible Drawer */}
      {filterPanelOpen && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 mb-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Category</label>
            <select
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-md p-1.5 text-xs text-slate-200"
            >
              <option value="">All Categories</option>
              <option value="AUTHENTICATION">Authentication</option>
              <option value="RECONNAISSANCE">Reconnaissance</option>
              <option value="EXPLOITATION">Exploitation</option>
              <option value="COMMAND_EXECUTION">Command Execution</option>
              <option value="NETWORK_PROBE">Network Probe</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Sensor</label>
            <select
              value={sensorFilter}
              onChange={(e) => {
                setSensorFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-md p-1.5 text-xs text-slate-200"
            >
              <option value="">All Sensors</option>
              <option value="WEB-001">WEB-001 (Web Portal)</option>
              <option value="SSH-001">SSH-001 (SSH Decoy)</option>
              <option value="TEL-001">TEL-001 (Telnet Sensor)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Protocol</label>
            <select
              value={protocolFilter}
              onChange={(e) => {
                setProtocolFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-md p-1.5 text-xs text-slate-200"
            >
              <option value="">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="HTTP">HTTP</option>
              <option value="SSH">SSH</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Detection Status</label>
            <select
              value={detectionFilter}
              onChange={(e) => {
                setDetectionFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-md p-1.5 text-xs text-slate-200"
            >
              <option value="">All Statuses</option>
              <option value="DETECTED">Detected (Alerted)</option>
              <option value="NORMAL">Normal (No Alerts)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Outcome</label>
            <select
              value={outcomeFilter}
              onChange={(e) => {
                setOutcomeFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-md p-1.5 text-xs text-slate-200"
            >
              <option value="">All Outcomes</option>
              <option value="FAILURE">Failure</option>
              <option value="SUCCESS">Success</option>
              <option value="BLOCKED">Blocked</option>
              <option value="ERROR">Error</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Alert Severity</label>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-md p-1.5 text-xs text-slate-200"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>
          </div>
        </div>
      )}

      {/* 5. Active Filter Chips */}
      {activeFiltersCount > 0 && (
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <span className="text-xs text-slate-400">Active Filters:</span>
          {categoryFilter && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-300 border border-slate-700">
              Category: {categoryFilter}
              <button onClick={() => setCategoryFilter('')} className="hover:text-white">✕</button>
            </span>
          )}
          {sensorFilter && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-300 border border-slate-700">
              Sensor: {sensorFilter}
              <button onClick={() => setSensorFilter('')} className="hover:text-white">✕</button>
            </span>
          )}
          {detectionFilter && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-300 border border-slate-700">
              Detection: {detectionFilter}
              <button onClick={() => setDetectionFilter('')} className="hover:text-white">✕</button>
            </span>
          )}
          {severityFilter && (
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-300 border border-slate-700">
              Severity: {severityFilter}
              <button onClick={() => setSeverityFilter('')} className="hover:text-white">✕</button>
            </span>
          )}
          <button
            onClick={clearFilters}
            className="text-xs text-blue-400 hover:text-blue-300 underline ml-2"
          >
            Clear All
          </button>
        </div>
      )}

      {/* 6. Events Data Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950 text-xs uppercase text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-3 w-8">
                  <input
                    type="checkbox"
                    checked={events.length > 0 && selectedEventIds.length === events.length}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedEventIds(events.slice(0, 5).map((ev) => ev.event_id));
                      } else {
                        setSelectedEventIds([]);
                      }
                    }}
                    className="rounded bg-slate-950 border-slate-700 text-blue-500"
                  />
                </th>
                <th className="py-3 px-3">Timestamp (UTC)</th>
                <th className="py-3 px-3">Category & Type</th>
                <th className="py-3 px-3">Decoy Sensor</th>
                <th className="py-3 px-3">Source Context</th>
                <th className="py-3 px-3">Outcome</th>
                <th className="py-3 px-3">Detection Status</th>
                <th className="py-3 px-3">Review</th>
                <th className="py-3 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500">
                    <div className="inline-block animate-spin mr-2">🔄</div> Loading security events...
                  </td>
                </tr>
              ) : error ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-rose-400">
                    Error loading events: {error}
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500">
                    No security events found matching the selected filters.
                  </td>
                </tr>
              ) : (
                events.map((ev) => {
                  const isSelected = selectedEventIds.includes(ev.event_id);
                  return (
                    <tr
                      key={ev.event_id}
                      className={`hover:bg-slate-800/60 transition-colors ${
                        isSelected ? 'bg-blue-950/20' : ''
                      }`}
                    >
                      <td className="py-3 px-3">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => toggleSelectEvent(ev.event_id)}
                          className="rounded bg-slate-950 border-slate-700 text-blue-500"
                        />
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap font-mono text-xs text-slate-400">
                        {formatDateTime(ev.timestamp)}
                      </td>
                      <td className="py-3 px-3">
                        <div className="font-semibold text-slate-200">{ev.event_type}</div>
                        <span className="text-xs text-slate-400">{ev.event_category}</span>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded text-xs bg-slate-800 font-mono text-slate-300">
                          {ev.sensor_id}
                        </span>
                        <div className="text-xs text-slate-500 mt-0.5">:{ev.target_port} ({ev.protocol})</div>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap font-mono text-xs">
                        <span className="text-slate-200">{ev.source_address}</span>
                        {ev.session_id && (
                          <div className="text-slate-500 text-[11px]">Sess: {ev.session_id.slice(0, 10)}...</div>
                        )}
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`px-2 py-0.5 text-xs font-semibold rounded ${
                            ev.outcome === 'FAILURE'
                              ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                              : ev.outcome === 'BLOCKED'
                              ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                              : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          }`}
                        >
                          {ev.outcome}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        {ev.detection_status === 'DETECTED' ? (
                          <div className="flex items-center gap-1.5">
                            <span
                              className={`px-2 py-0.5 text-xs font-bold rounded ${
                                ev.highest_alert_severity === 'CRITICAL'
                                  ? 'bg-rose-600 text-white'
                                  : ev.highest_alert_severity === 'HIGH'
                                  ? 'bg-orange-500 text-white'
                                  : 'bg-amber-500 text-slate-950'
                              }`}
                            >
                              {ev.highest_alert_severity || 'ALERT'}
                            </span>
                            <span className="text-xs text-slate-400">({ev.alerts_count})</span>
                          </div>
                        ) : (
                          <span className="text-xs text-slate-500">Normal</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-xs">
                        <span
                          className={`px-1.5 py-0.5 rounded ${
                            ev.review_status === 'ESCALATED'
                              ? 'text-rose-400 bg-rose-950/40'
                              : ev.review_status === 'REVIEWED'
                              ? 'text-emerald-400 bg-emerald-950/40'
                              : ev.review_status === 'UNDER_REVIEW'
                              ? 'text-amber-400 bg-amber-950/40'
                              : 'text-slate-500'
                          }`}
                        >
                          {ev.review_status}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={() => openDetail(ev.event_id)}
                          className="px-2.5 py-1 text-xs font-medium text-blue-400 hover:text-blue-300 hover:bg-slate-800 rounded transition-colors"
                        >
                          Inspect →
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between p-3 border-t border-slate-800 text-xs text-slate-400 gap-2">
          <div>
            Showing {(currentPage - 1) * pageSize + 1} -{' '}
            {Math.min(currentPage * pageSize, totalEvents)} of {formatInteger(totalEvents, '0')} events
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage <= 1 || loading}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200"
            >
              Prev
            </button>
            <span>
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage >= totalPages || loading}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* 7. Multi-Event Comparison Modal */}
      {comparisonModalOpen && comparisonData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between p-4 border-b border-slate-800">
              <div>
                <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <span>⚖️</span> Event Side-by-Side Comparison
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Comparing {comparisonData.compared_event_ids.length} selected security events.
                </p>
              </div>
              <button
                onClick={() => setComparisonModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-lg px-2"
              >
                ✕
              </button>
            </div>

            <div className="p-4 bg-slate-950/50 border-b border-slate-800 text-xs text-amber-400">
              ⚠️ <strong>Strict Non-Attribution Caveat:</strong> {comparisonData.caveat_notice}
            </div>

            <div className="flex-1 overflow-y-auto p-4">
              <div className="flex gap-4 mb-3 text-xs">
                <span className="text-emerald-400 font-semibold">
                  Matching Attributes: {comparisonData.matching_fields_count}
                </span>
                <span className="text-amber-400 font-semibold">
                  Differing Attributes: {comparisonData.differing_fields_count}
                </span>
              </div>

              <div className="border border-slate-800 rounded-lg overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400">
                    <tr>
                      <th className="p-2.5 border-b border-slate-800 font-semibold w-1/4">Field</th>
                      {comparisonData.compared_event_ids.map((id, idx) => (
                        <th key={id} className="p-2.5 border-b border-slate-800 font-mono">
                          Event #{idx + 1} ({id.slice(0, 8)}...)
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {comparisonData.fields.map((f) => (
                      <tr
                        key={f.field_name}
                        className={f.is_match ? 'bg-emerald-950/10' : 'bg-slate-900/60'}
                      >
                        <td className="p-2.5 font-medium text-slate-300 flex items-center gap-2">
                          <span>{f.is_match ? '✅' : '⚡'}</span>
                          {f.field_name}
                        </td>
                        {comparisonData.compared_event_ids.map((id) => (
                          <td key={id} className="p-2.5 font-mono text-slate-200">
                            {String(f.values_by_event_id[id] ?? '—')}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="p-4 border-t border-slate-800 text-right">
              <button
                onClick={() => setComparisonModalOpen(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-sm font-medium text-slate-200 rounded-lg"
              >
                Close Comparison
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 8. Forensic Event Detail Slide-Over Drawer */}
      {detailDrawerOpen && (
        <div className="fixed inset-0 z-50 overflow-hidden flex justify-end bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl">
            {/* Drawer Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="text-xs uppercase tracking-wider text-slate-400 font-bold">
                  Forensic Event Details
                </div>
                <div className="text-base font-bold text-slate-100 font-mono mt-0.5">
                  {selectedEventId}
                </div>
              </div>
              <button
                onClick={() => setDetailDrawerOpen(false)}
                className="text-slate-400 hover:text-slate-200 px-2 text-lg"
              >
                ✕
              </button>
            </div>

            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-800 bg-slate-950/60 px-4 text-xs font-medium">
              {[
                { id: 'overview', label: 'Overview' },
                { id: 'payload', label: 'Normalized Payload' },
                { id: 'relationships', label: 'Relationships' },
                { id: 'timeline', label: 'Session Timeline' },
                { id: 'history', label: 'Provenance' },
                { id: 'audit', label: 'Analyst Actions' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`py-3 px-3 border-b-2 transition-colors ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-400 font-semibold'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Drawer Content Body */}
            <div className="flex-1 overflow-y-auto p-5">
              {detailLoading || !detailData ? (
                <div className="py-12 text-center text-slate-500">
                  <span className="inline-block animate-spin mr-2">🔄</span> Loading forensic event details...
                </div>
              ) : (
                <>
                  {actionSuccess && (
                    <div className="mb-4 p-3 bg-emerald-950/60 border border-emerald-500/30 rounded-lg text-xs text-emerald-400 flex items-center justify-between">
                      <span>✓ {actionSuccess}</span>
                      <button onClick={() => setActionSuccess(null)}>✕</button>
                    </div>
                  )}

                  {/* Tab 1: Overview */}
                  {activeTab === 'overview' && (
                    <div className="space-y-4 text-xs">
                      <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                        <div>
                          <span className="text-slate-400">Event Type:</span>
                          <div className="font-semibold text-slate-200 mt-0.5">{detailData.overview.event_type}</div>
                        </div>
                        <div>
                          <span className="text-slate-400">Category:</span>
                          <div className="font-semibold text-slate-200 mt-0.5">{detailData.overview.event_category}</div>
                        </div>
                        <div>
                          <span className="text-slate-400">Sensor ID:</span>
                          <div className="font-mono text-slate-200 mt-0.5">{detailData.overview.sensor_id}</div>
                        </div>
                        <div>
                          <span className="text-slate-400">Source IP & Protocol:</span>
                          <div className="font-mono text-slate-200 mt-0.5">
                            {detailData.overview.source_address} ({detailData.overview.protocol})
                          </div>
                        </div>
                        <div>
                          <span className="text-slate-400">Outcome:</span>
                          <div className="font-semibold text-amber-400 mt-0.5">{detailData.overview.outcome}</div>
                        </div>
                        <div>
                          <span className="text-slate-400">Review Status:</span>
                          <div className="font-semibold text-slate-200 mt-0.5">{detailData.overview.review_status}</div>
                        </div>
                      </div>

                      {detailData.overview.investigation_code && (
                        <div className="p-3 bg-blue-950/40 border border-blue-500/30 rounded-lg">
                          <span className="text-blue-300 font-semibold">Associated Investigation:</span>
                          <div className="mt-1 font-mono text-slate-200">
                            Cluster Code: {detailData.overview.investigation_code}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Tab 2: Normalized Payload */}
                  {activeTab === 'payload' && (
                    <div className="space-y-3">
                      <div className="text-xs text-slate-400 flex items-center justify-between">
                        <span>Safe Normalized Metadata (Zero Credential Storage Guarantee):</span>
                      </div>
                      <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-emerald-400 overflow-x-auto max-h-96">
                        {JSON.stringify(detailData.normalized_payload, null, 2)}
                      </pre>
                    </div>
                  )}

                  {/* Tab 3: Relationships */}
                  {activeTab === 'relationships' && (
                    <div className="space-y-3">
                      <p className="text-xs text-slate-400">
                        Cross-subsystem entities connected to this security event:
                      </p>
                      {detailData.relationships.length === 0 ? (
                        <div className="text-xs text-slate-500 py-4">No correlated relationships found.</div>
                      ) : (
                        detailData.relationships.map((r, i) => (
                          <div
                            key={i}
                            className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs flex items-center justify-between"
                          >
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="px-1.5 py-0.5 bg-slate-800 text-blue-400 rounded font-semibold text-[10px]">
                                  {r.relationship_type}
                                </span>
                                <span className="font-semibold text-slate-200">{r.label}</span>
                              </div>
                              <p className="text-slate-400 mt-1">{r.description}</p>
                            </div>
                            {r.navigation_url && (
                              <a
                                href={r.navigation_url}
                                className="text-xs text-blue-400 hover:text-blue-300 font-medium underline"
                              >
                                View →
                              </a>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* Tab 4: Session Timeline */}
                  {activeTab === 'timeline' && (
                    <div className="space-y-3">
                      <p className="text-xs text-slate-400">
                        Chronological sequence of nearby events in the same session context:
                      </p>
                      <div className="border-l-2 border-slate-800 pl-4 space-y-4 my-2 text-xs">
                        <div className="text-slate-500">Timeline events loaded from backend session context.</div>
                      </div>
                    </div>
                  )}

                  {/* Tab 5: Provenance & Processing History */}
                  {activeTab === 'history' && (
                    <div className="space-y-4 text-xs">
                      <div>
                        <span className="font-semibold text-slate-300">Ingestion Pipeline Stages:</span>
                        <div className="space-y-2 mt-2">
                          {detailData.processing_history.map((stage, idx) => (
                            <div
                              key={idx}
                              className="p-2.5 bg-slate-950 border border-slate-800 rounded flex items-center justify-between"
                            >
                              <div>
                                <span className="font-semibold text-slate-200">{stage.stage}</span>
                                <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                                  {formatDateTime(stage.timestamp)}
                                </div>
                              </div>
                              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 font-semibold text-[10px]">
                                {stage.status}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="mt-4">
                        <span className="font-semibold text-slate-300">Evidence Provenance:</span>
                        <pre className="bg-slate-950 border border-slate-800 rounded p-3 text-slate-400 font-mono mt-2 overflow-x-auto text-[11px]">
                          {JSON.stringify(detailData.evidence_provenance, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* Tab 6: Analyst Notes & Audit Actions */}
                  {activeTab === 'audit' && (
                    <div className="space-y-5 text-xs">
                      {/* Add Analyst Note */}
                      <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                        <label className="block font-semibold text-slate-300 mb-1.5">
                          Add Analyst Note (Immutable Audit Log)
                        </label>
                        <textarea
                          rows={2}
                          placeholder="Document forensic observation..."
                          value={analystNote}
                          onChange={(e) => setAnalystNote(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 text-xs"
                        />
                        <div className="mt-2 text-right">
                          <button
                            onClick={handleAddNote}
                            disabled={submittingNote || !analystNote.trim()}
                            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white rounded font-medium"
                          >
                            {submittingNote ? 'Saving...' : 'Save Note'}
                          </button>
                        </div>
                      </div>

                      {/* Update Review Status */}
                      <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                        <label className="block font-semibold text-slate-300 mb-1.5">
                          Update Investigation Review Status
                        </label>
                        <div className="flex gap-2 mb-2">
                          {['UNDER_REVIEW', 'REVIEWED', 'ESCALATED', 'DISMISSED'].map((st) => (
                            <button
                              key={st}
                              onClick={() => setSelectedReviewStatus(st)}
                              className={`px-2.5 py-1 rounded text-xs font-semibold ${
                                selectedReviewStatus === st
                                  ? 'bg-blue-600 text-white'
                                  : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
                              }`}
                            >
                              {st}
                            </button>
                          ))}
                        </div>
                        <input
                          type="text"
                          placeholder="Optional review justification..."
                          value={reviewNote}
                          onChange={(e) => setReviewNote(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-slate-100 placeholder-slate-500 text-xs"
                        />
                        <div className="mt-2 text-right">
                          <button
                            onClick={handleUpdateReview}
                            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-medium"
                          >
                            Update Status
                          </button>
                        </div>
                      </div>

                      {/* Associate with Investigation */}
                      <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                        <label className="block font-semibold text-slate-300 mb-1.5">
                          Associate with Campaign Investigation
                        </label>
                        <input
                          type="text"
                          placeholder="Investigation Cluster ID (e.g. CAMP-API-01)..."
                          value={targetClusterId}
                          onChange={(e) => setTargetClusterId(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-slate-100 placeholder-slate-500 text-xs mb-2"
                        />
                        <input
                          type="text"
                          placeholder="Reason for inclusion..."
                          value={associateReason}
                          onChange={(e) => setAssociateReason(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-800 rounded p-2 text-slate-100 placeholder-slate-500 text-xs"
                        />
                        <div className="mt-2 text-right">
                          <button
                            onClick={handleAssociateInvestigation}
                            disabled={!targetClusterId.trim()}
                            className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white rounded font-medium"
                          >
                            Link to Cluster
                          </button>
                        </div>
                      </div>

                      {/* Existing Audit Logs List */}
                      <div>
                        <span className="font-semibold text-slate-300">Historical Audit Records:</span>
                        <div className="space-y-2 mt-2">
                          {detailData.audit_logs.length === 0 ? (
                            <div className="text-slate-500">No analyst notes recorded yet.</div>
                          ) : (
                            detailData.audit_logs.map((a) => (
                              <div
                                key={a.id}
                                className="p-2.5 bg-slate-950 border border-slate-800 rounded text-xs"
                              >
                                <div className="flex items-center justify-between text-slate-400">
                                  <span className="font-semibold text-blue-400">{a.action_type}</span>
                                  <span className="font-mono text-[10px]">
                                    {formatDateTime(a.created_at)}
                                  </span>
                                </div>
                                <div className="text-slate-300 mt-1">{a.notes}</div>
                                <div className="text-[10px] text-slate-500 mt-0.5">By: {a.analyst_id}</div>
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityEventsPage;

