/**
 * AI Adaptive Cyber Deception Dashboard — Core Client Application
 * Handles API integration, dynamic view rendering, interactive SVG attack graph,
 * session exploration, and simulated world-state tracking.
 */

(() => {
  "use strict";

  // Application State
  const state = {
    data: null,
    scenarios: [],
    selectedSource: "scenario",
    selectedSessionId: null,
    searchQuery: "",
    selectedCategory: "ALL",
    selectedScoreRange: "ALL",
    graphZoom: 1,
    graphPan: { x: 0, y: 0 },
    isDraggingGraph: false,
    dragStart: { x: 0, y: 0 },
  };

  // DOM Elements Cache
  const els = {
    sourceSelect: document.getElementById("sourceSelect"),
    sourceBadge: document.getElementById("sourceBadge"),
    statusBadge: document.getElementById("statusBadge"),
    statusBadgeText: document.getElementById("statusBadgeText"),
    scenarioControlsGroup: document.getElementById("scenarioControlsGroup"),
    scenarioSelect: document.getElementById("scenarioSelect"),
    accumulateToggle: document.getElementById("accumulateToggle"),
    btnRunScenario: document.getElementById("btnRunScenario"),
    btnRefresh: document.getElementById("btnRefresh"),
    btnResetState: document.getElementById("btnResetState"),
    btnExport: document.getElementById("btnExport"),
    linkSimulator: document.getElementById("linkSimulator"),
    navTabs: document.querySelectorAll(".nav-tab"),
    tabPanes: document.querySelectorAll(".tab-pane"),
    toastContainer: document.getElementById("toastContainer"),
  };

  // =========================================================================
  // API Client
  // =========================================================================

  async function apiRequest(endpoint, options = {}) {
    try {
      const res = await fetch(endpoint, options);
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(errorData.detail || `HTTP ${res.status}: ${res.statusText}`);
      }
      return await res.json();
    } catch (err) {
      showToast(err.message, "error");
      throw err;
    }
  }

  function updateHeaderStatusBadge() {
    if (!els.statusBadge || !els.statusBadgeText) return;
    const source = state.selectedSource;
    const data = state.data;
    const dotSvg = els.statusBadge.querySelector("svg");

    if (source === "simulator") {
      els.statusBadge.className = "safety-pill status-simulator";
      els.statusBadgeText.textContent = "Simulated Attacker Environment (In-Memory)";
      if (dotSvg) dotSvg.style.color = "var(--accent-copper)";
      return;
    }

    if (source === "scenario") {
      els.statusBadge.className = "safety-pill status-scenario";
      els.statusBadgeText.textContent = "Simulated Fictional Environment (Offline)";
      if (dotSvg) dotSvg.style.color = "var(--accent-emerald)";
      return;
    }

    if (source === "live_cowrie") {
      const health = (data && data.health) || (data && data.live_health) || null;
      const eventsCount = (data && typeof data.events_parsed === "number")
        ? data.events_parsed
        : ((health && typeof health.total_events_ingested === "number") ? health.total_events_ingested : 0);

      const isUnhealthy = health && (
        health.status === "error" ||
        health.status === "tailer_path_unreachable" ||
        Boolean(health.last_error) ||
        (health.tailer && health.tailer.file_exists === false)
      );

      if (isUnhealthy) {
        els.statusBadge.className = "safety-pill status-live-unhealthy";
        els.statusBadgeText.textContent = "Live Telemetry: Disconnected / Unreachable";
        if (dotSvg) dotSvg.style.color = "var(--accent-rose)";
      } else if (eventsCount > 0) {
        els.statusBadge.className = "safety-pill status-live-connected";
        els.statusBadgeText.textContent = `Live Cowrie Connected & Receiving (${eventsCount} Events)`;
        if (dotSvg) dotSvg.style.color = "var(--accent-emerald)";
      } else {
        els.statusBadge.className = "safety-pill status-live-waiting";
        els.statusBadgeText.textContent = "Live Telemetry: Waiting for Events";
        if (dotSvg) dotSvg.style.color = "var(--accent-amber)";
      }
    }
  }

  function updateSourceUI() {
    const isSimulator = state.selectedSource === "simulator";
    const isLiveCowrie = state.selectedSource === "live_cowrie";
    if (els.sourceSelect) {
      els.sourceSelect.value = state.selectedSource;
    }
    if (els.sourceBadge) {
      let badgeClass = "source-badge";
      let defaultLabel = "Synthetic Scenarios";
      if (isSimulator) {
        badgeClass = "source-badge badge-simulator";
        defaultLabel = "Attacker Simulator";
      } else if (isLiveCowrie) {
        badgeClass = "source-badge badge-live";
        defaultLabel = "Live Cowrie Honeypot";
      }
      const label = (state.data && state.data.source_label)
        ? state.data.source_label
        : defaultLabel;
      els.sourceBadge.textContent = `Source: ${label}`;
      els.sourceBadge.className = badgeClass;
    }
    if (els.scenarioControlsGroup) {
      els.scenarioControlsGroup.style.display = (isSimulator || isLiveCowrie) ? "none" : "flex";
    }
    updateHeaderStatusBadge();
  }

  async function fetchScenarios() {
    try {
      state.scenarios = await apiRequest("/api/scenarios");
      if (els.scenarioSelect) {
        els.scenarioSelect.innerHTML = "";

        if (state.scenarios.length === 0) {
          els.scenarioSelect.innerHTML = '<option value="">No scenarios available</option>';
          return;
        }

        state.scenarios.forEach((s) => {
          const opt = document.createElement("option");
          opt.value = s.filename;
          opt.textContent = `${s.name} (${s.filename})`;
          els.scenarioSelect.appendChild(opt);
        });
      }
    } catch (err) {
      console.error("Failed to load scenarios:", err);
    }
  }

  async function fetchCurrentState() {
    try {
      const url = state.selectedSource
        ? `/api/current-state?source=${encodeURIComponent(state.selectedSource)}`
        : `/api/current-state`;
      const data = await apiRequest(url);
      if (data && data.loaded) {
        state.data = data;
        if (data.source) {
          state.selectedSource = data.source;
        }
        if (data.sessions && data.sessions.length > 0 && !state.selectedSessionId) {
          state.selectedSessionId = data.sessions[0].session_id;
        }
      } else {
        state.data = data;
      }
      updateSourceUI();
      renderAllViews();
    } catch (err) {
      console.error("Failed to load current state:", err);
    }
  }

  function handleSourceChange(e) {
    state.selectedSource = e.target.value;
    state.selectedSessionId = null;
    fetchCurrentState();
  }

  async function handleRefresh() {
    if (els.btnRefresh) {
      els.btnRefresh.disabled = true;
      els.btnRefresh.innerHTML = '<span class="spinner"></span> Refreshing...';
    }
    try {
      await fetchCurrentState();
      showToast("Telemetry refreshed.", "info");
    } finally {
      if (els.btnRefresh) {
        els.btnRefresh.disabled = false;
        els.btnRefresh.innerHTML = '&#8635; Refresh';
      }
    }
  }

  async function handleRunScenario() {
    const scenario = els.scenarioSelect ? els.scenarioSelect.value : "";
    if (!scenario) {
      showToast("Please select a scenario to run.", "warning");
      return;
    }

    const accumulate = els.accumulateToggle ? els.accumulateToggle.checked : false;
    els.btnRunScenario.disabled = true;
    els.btnRunScenario.innerHTML = '<span class="spinner"></span> Running...';

    try {
      const result = await apiRequest("/api/run-scenario", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario, accumulate_state: accumulate }),
      });

      state.selectedSource = "scenario";
      state.data = { loaded: true, ...result };
      if (result.sessions && result.sessions.length > 0) {
        state.selectedSessionId = result.sessions[0].session_id;
      }

      showToast(`Scenario '${scenario}' processed successfully!`, "success");
      updateSourceUI();
      renderAllViews();
    } catch (err) {
      // Handled in apiRequest
    } finally {
      els.btnRunScenario.disabled = false;
      els.btnRunScenario.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run Scenario';
    }
  }

  async function handleResetState() {
    const isSim = state.selectedSource === "simulator";
    const isLive = state.selectedSource === "live_cowrie";
    let promptMsg = "Reset simulated world state and clear scenario results?";
    if (isSim) {
      promptMsg = "Reset Linux Attacker Simulator sessions and restore fictional baseline?";
    } else if (isLive) {
      promptMsg = "Clear ingested Live Cowrie telemetry events and reset analysis buffer?";
    }
    if (!confirm(promptMsg)) return;

    try {
      await apiRequest(`/api/reset?target=${state.selectedSource}`, { method: "POST" });
      state.data = null;
      state.selectedSessionId = null;
      const targetName = isSim ? "Simulator" : (isLive ? "Live Cowrie telemetry" : "Scenario");
      showToast(`${targetName} environment reset to initial baseline.`, "info");
      await fetchCurrentState();
    } catch (err) {
      // Handled in apiRequest
    }
  }

  function handleExport() {
    if (!state.data || !state.data.loaded) {
      showToast("No active scenario or simulator results to export.", "warning");
      return;
    }
    window.location.href = `/api/export?source=${encodeURIComponent(state.selectedSource)}`;
  }

  // =========================================================================
  // View Rendering
  // =========================================================================

  function renderAllViews() {
    renderOverview();
    renderSessionExplorer();
    renderAttackGraph();
    renderTimeline();
    renderBehaviourAnalysis();
    renderDeceptionPlanner();
    renderReports();
  }

  // --- 1. Overview View ---
  function renderOverview() {
    const container = document.getElementById("pane-overview");
    if (!state.data || !state.data.loaded) {
      if (state.selectedSource === "simulator") {
        container.innerHTML = `
          <div class="empty-state card">
            <span class="empty-source-pill">&#128421; Active View: Attacker Simulator</span>
            <div class="empty-icon">&#128421;</div>
            <div class="empty-title">No Attacker Simulator Telemetry Active</div>
            <div class="empty-desc">
              The Linux Attacker Simulator runs at <code>/simulator/</code>. Execute commands or run a scenario action in the simulator, then click <strong>Refresh</strong> to view live events, findings, threat scores, and deception decisions.
            </div>
            <div style="display: flex; gap: 0.75rem; justify-content: center; margin-top: 0.5rem; flex-wrap: wrap;">
              <a href="/simulator/" target="_blank" class="btn btn-primary" style="text-decoration: none;">
                &#128421; Open Simulator &#8599;
              </a>
              <button class="btn btn-secondary" onclick="document.getElementById('btnRefresh').click()">
                &#8635; Refresh Telemetry
              </button>
            </div>
          </div>
        `;
      } else if (state.selectedSource === "live_cowrie") {
        const health = (state.data && state.data.health) || (state.data && state.data.live_health) || {};
        const isUnhealthy = health && (
          health.status === "error" ||
          health.status === "tailer_path_unreachable" ||
          Boolean(health.last_error) ||
          (health.tailer && health.tailer.file_exists === false)
        );

        let statusTitle = "Waiting for Live Cowrie Telemetry";
        let statusBadgeText = "WAITING FOR INGESTION";
        let statusBadgeColor = "var(--accent-amber)";

        if (isUnhealthy) {
          statusTitle = "Live Telemetry Unreachable / Disconnected";
          statusBadgeText = "DISCONNECTED / UNREACHABLE";
          statusBadgeColor = "var(--accent-rose)";
        } else if (health.connected) {
          statusTitle = "Collector Connected — Waiting for Cowrie Events";
          statusBadgeText = "CONNECTED (LISTENING)";
          statusBadgeColor = "var(--accent-emerald)";
        }

        container.innerHTML = `
          <div class="empty-state card">
            <span class="empty-source-pill" style="border-color: ${statusBadgeColor}; color: ${statusBadgeColor};">
              &#128225; Active View: Live Cowrie Honeypot
            </span>
            <div class="empty-icon" style="color: ${statusBadgeColor};">&#128225;</div>
            <div class="empty-title">${escapeHtml(statusTitle)}</div>
            <div class="empty-desc">
              The analysis pipeline is running in <strong>read-only mode</strong>. Send Cowrie JSON events to <code>/api/telemetry/ingest</code> using the Ubuntu collector (<code>python telemetry/collector.py</code>) or direct log tailing.
            </div>
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: var(--radius-sm); padding: 0.85rem 1.15rem; max-width: 520px; width: 100%; margin: 0 auto 1.25rem; font-size: 0.82rem; text-align: left; font-family: var(--font-mono); line-height: 1.6;">
              <div>&bull; Collector Status: <span style="color: ${statusBadgeColor}; font-weight: 600;">${statusBadgeText}</span></div>
              <div>&bull; Honeypot Safety: <span style="color: var(--accent-emerald); font-weight: 600;">READ-ONLY (Honeypot Unmodified)</span></div>
              <div>&bull; Last Collection: <span style="color: var(--text-muted);">${escapeHtml(health.last_ingested_at || health.last_ingest_time || 'None recorded')}</span></div>
              <div>&bull; Ingested Count: <span style="color: var(--text-muted);">${health.total_events_ingested || 0} events</span></div>
              <div>&bull; Parse Diagnostics: <span style="color: var(--text-muted);">${health.warnings_count || 0} warning(s)</span></div>
            </div>
            <div style="display: flex; gap: 0.75rem; justify-content: center; margin-top: 0.5rem; flex-wrap: wrap;">
              <button class="btn btn-secondary" onclick="document.getElementById('btnRefresh').click()">
                &#8635; Check for Telemetry
              </button>
            </div>
          </div>
        `;
      } else {
        container.innerHTML = `
          <div class="empty-state card">
            <span class="empty-source-pill">&#128737; Active View: Synthetic Scenarios</span>
            <div class="empty-icon">&#128737;</div>
            <div class="empty-title">No Scenario Telemetry Loaded</div>
            <div class="empty-desc">
              Select an approved synthetic scenario from the control bar above and click <strong>Run Scenario</strong>
              to evaluate offline parser events, behaviour classification, heuristic scoring, and safe deception planning.
            </div>
            <button class="btn btn-primary" onclick="document.getElementById('btnRunScenario').click()">
              Run Selected Scenario
            </button>
          </div>
        `;
      }
      return;
    }

    const { events_parsed, sessions_count, sessions, world_state } = state.data;
    const scores = sessions.map((s) => s.analysis.score);
    const avgScore = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;

    // Category Distribution
    const catCounts = {};
    sessions.forEach((s) => {
      const cat = s.analysis.primary_category || "unknown";
      catCounts[cat] = (catCounts[cat] || 0) + 1;
    });

    // Score Buckets
    let low = 0, med = 0, high = 0;
    scores.forEach((sc) => {
      if (sc <= 25) low++;
      else if (sc <= 70) med++;
      else high++;
    });

    const isSim = state.data.source === "simulator";
    const isLive = state.data.source === "live_cowrie";
    const sourceLabel = state.data.source_label || (isSim ? "Attacker Simulator" : (isLive ? "Live Cowrie Honeypot" : "Synthetic Scenarios"));
    const health = (isLive && state.data.health) ? state.data.health : null;

    // Deception Action & Recommendation Semantics:
    // Count only actions that the backend confirms were executed.
    // For live telemetry (read-only), display RECOMMENDATIONS GENERATED.
    const metricInfo = state.data.deception_metric || {};
    const history = (world_state && world_state.action_history) || [];
    const nonNoOpActions = history.filter((a) => a.action_id && a.action_id !== "no_op" && a.success !== false);

    let metricLabel = "DECEPTION ACTIONS EXECUTED";
    let metricValue = nonNoOpActions.length;
    let metricNote = isSim ? "Applied to simulated environment" : "Simulated world state transitions";

    if (isLive || metricInfo.is_advisory) {
      metricLabel = "RECOMMENDATIONS GENERATED";
      metricValue = typeof metricInfo.value === "number" ? metricInfo.value : nonNoOpActions.length;
      metricNote = metricInfo.status_note || "Read-Only: 0 actions executed on real honeypot";
    } else if (typeof metricInfo.value === "number") {
      metricValue = metricInfo.value;
      metricLabel = metricInfo.label || "DECEPTION ACTIONS EXECUTED";
      metricNote = metricInfo.status_note || metricNote;
    }

    container.innerHTML = `
      <div class="source-banner" style="${isLive ? 'border-left: 3px solid var(--accent-emerald);' : ''}">
        <div>
          <strong>Active Telemetry Source:</strong> ${escapeHtml(sourceLabel)}
          <span style="margin-left: 0.5rem; opacity: 0.75;">(${escapeHtml(state.data.input_file || "in-memory")})</span>
          ${isLive ? `
            <div style="font-size: 0.75rem; color: var(--accent-emerald); margin-top: 0.2rem; font-family: var(--font-mono);">
              &#128737; READ-ONLY LIVE TELEMETRY &bull; Honeypot untouched &bull; Recommendations advisory only
            </div>
          ` : ''}
        </div>
        <div style="text-align: right;">
          <span class="source-badge ${isSim ? 'badge-simulator' : (isLive ? 'badge-live' : '')}">
            ${sessions_count} Session(s) &bull; ${events_parsed} Events
          </span>
          ${health && health.last_ingested_at ? `
            <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.2rem; font-family: var(--font-mono);">
              Last collection: ${escapeHtml(health.last_ingested_at)}
            </div>
          ` : ''}
        </div>
      </div>

      <div class="grid-metrics">
        <div class="card metric-card">
          <div class="metric-icon-box" style="background: var(--accent-copper-tint); color: var(--accent-copper);">
            &#128187;
          </div>
          <div class="metric-data">
            <div class="metric-value">${sessions_count}</div>
            <div class="metric-label">Attacker Sessions</div>
          </div>
        </div>

        <div class="card metric-card">
          <div class="metric-icon-box" style="background: var(--bg-surface); color: var(--text-secondary);">
            &#128225;
          </div>
          <div class="metric-data">
            <div class="metric-value">${events_parsed}</div>
            <div class="metric-label">Normalized Events</div>
          </div>
        </div>

        <div class="card metric-card">
          <div class="metric-icon-box" style="background: var(--accent-amber-tint); color: var(--accent-amber);">
            &#9888;
          </div>
          <div class="metric-data">
            <div class="metric-value">${avgScore}/100</div>
            <div class="metric-label">Avg Threat Index</div>
          </div>
        </div>

        <div class="card metric-card">
          <div class="metric-icon-box" style="background: ${isLive ? 'var(--accent-amber-tint)' : 'var(--accent-emerald-tint)'}; color: ${isLive ? 'var(--accent-amber)' : 'var(--accent-emerald)'};">
            ${isLive ? '&#128161;' : '&#128273;'}
          </div>
          <div class="metric-data">
            <div class="metric-value">${metricValue}</div>
            <div class="metric-label">${escapeHtml(metricLabel)}</div>
            <div style="font-size: 0.68rem; color: var(--text-muted); margin-top: 0.15rem;">
              ${escapeHtml(metricNote)}
            </div>
          </div>
        </div>
      </div>

      <div class="grid-2col">
        <div class="card">
          <div class="card-header">
            <div class="card-title">&#128394; Behaviour Category Distribution</div>
            <span class="card-badge">${Object.keys(catCounts).length} Categories</span>
          </div>
          <div style="display: flex; flex-direction: column; gap: 0.65rem;">
            ${Object.entries(catCounts).map(([cat, count]) => {
              const pct = Math.round((count / sessions_count) * 100);
              return `
                <div>
                  <div style="display: flex; justify-content: space-between; font-size: 0.78rem; margin-bottom: 0.2rem;">
                    <span class="badge cat-${cat}">${cat}</span>
                    <span style="font-family: var(--font-mono); color: var(--text-secondary);">${count} session(s) (${pct}%)</span>
                  </div>
                  <div style="width: 100%; height: 5px; background: var(--bg-surface); border-radius: var(--radius-full); overflow: hidden;">
                    <div style="width: ${pct}%; height: 100%; background: var(--accent-copper); border-radius: var(--radius-full);"></div>
                  </div>
                </div>
              `;
            }).join("")}
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div class="card-title">&#128202; Heuristic Threat Score Severity</div>
            <span class="card-badge">Range: 0–100</span>
          </div>
          <div style="display: flex; gap: 0.75rem; margin-top: 0.75rem;">
            <div style="flex: 1; background: var(--bg-surface); padding: 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--accent-emerald-border); text-align: center;">
              <div style="font-size: 1.4rem; font-weight: 700; color: var(--accent-emerald); font-family: var(--font-mono);">${low}</div>
              <div style="font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase;">Low (0–25)</div>
            </div>
            <div style="flex: 1; background: var(--bg-surface); padding: 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--accent-amber-border); text-align: center;">
              <div style="font-size: 1.4rem; font-weight: 700; color: var(--accent-amber); font-family: var(--font-mono);">${med}</div>
              <div style="font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase;">Moderate (26–70)</div>
            </div>
            <div style="flex: 1; background: var(--bg-surface); padding: 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--accent-rose-border); text-align: center;">
              <div style="font-size: 1.4rem; font-weight: 700; color: var(--accent-rose); font-family: var(--font-mono);">${high}</div>
              <div style="font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase;">Elevated (71–100)</div>
            </div>
          </div>
          <p style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.75rem; line-height: 1.4;">
            *Note: Explainable heuristic index derived from observed behavioral commands and brute-force counts, not a statistical compromise probability.
          </p>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">&#128392; Recent Attacker Sessions Overview</div>
          <span class="card-badge">${sessions.length} Evaluated</span>
        </div>
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th>Session ID</th>
                <th>Source IP</th>
                <th>Events</th>
                <th>Primary Behaviour</th>
                <th>Threat Score</th>
                <th>Deception Policy</th>
                <th>Action Status</th>
              </tr>
            </thead>
            <tbody>
              ${sessions.map((s) => `
                <tr style="cursor: pointer;" onclick="selectSession('${s.session_id}')">
                  <td style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-copper);">${escapeHtml(s.session_id)}</td>
                  <td style="font-family: var(--font-mono);">${escapeHtml(s.source_ip || "unknown")}</td>
                  <td>${s.event_count}</td>
                  <td><span class="badge cat-${s.analysis.primary_category}">${s.analysis.primary_category}</span></td>
                  <td><span class="score-badge ${getScoreClass(s.analysis.score)}">${s.analysis.score}</span></td>
                  <td style="font-family: var(--font-mono); font-size: 0.75rem;">${s.deception.policy_id}</td>
                  <td><span class="badge badge-${s.deception.status === 'accepted' ? 'accepted' : 'noop'}">${s.deception.status}</span></td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // --- 2. Session Explorer View ---
  function renderSessionExplorer() {
    const container = document.getElementById("pane-sessions");
    if (!state.data || !state.data.loaded) {
      container.innerHTML = `<div class="empty-state card"><div class="empty-title">No Sessions Available</div><div class="empty-desc">Load a synthetic scenario to explore session details.</div></div>`;
      return;
    }

    const { sessions } = state.data;
    const query = state.searchQuery.toLowerCase().trim();
    const catFilter = state.selectedCategory;
    const scoreFilter = state.selectedScoreRange;

    // Filter sessions
    const filtered = sessions.filter((s) => {
      const matchQuery = !query || s.session_id.toLowerCase().includes(query) || (s.source_ip && s.source_ip.includes(query));
      const matchCat = catFilter === "ALL" || s.analysis.primary_category === catFilter;
      let matchScore = true;
      if (scoreFilter === "LOW") matchScore = s.analysis.score <= 25;
      else if (scoreFilter === "MED") matchScore = s.analysis.score > 25 && s.analysis.score <= 70;
      else if (scoreFilter === "HIGH") matchScore = s.analysis.score > 70;
      return matchQuery && matchCat && matchScore;
    });

    const activeSession = sessions.find((s) => s.session_id === state.selectedSessionId) || (filtered.length ? filtered[0] : null);

    container.innerHTML = `
      <div class="explorer-layout">
        <!-- Left: Filters & Session List -->
        <div>
          <div class="session-filter-bar">
            <input type="text" class="input-search" id="sessionSearchInput" placeholder="Filter session ID / IP..." value="${escapeHtml(state.searchQuery)}">
            <select class="select-control" id="catFilterSelect" style="padding-right: 1.5rem;">
              <option value="ALL" ${catFilter === 'ALL' ? 'selected' : ''}>All Categories</option>
              <option value="reconnaissance" ${catFilter === 'reconnaissance' ? 'selected' : ''}>Reconnaissance</option>
              <option value="authentication_abuse" ${catFilter === 'authentication_abuse' ? 'selected' : ''}>Auth Abuse</option>
              <option value="file_discovery" ${catFilter === 'file_discovery' ? 'selected' : ''}>File Discovery</option>
              <option value="download_attempt" ${catFilter === 'download_attempt' ? 'selected' : ''}>Download</option>
              <option value="privilege_escalation_attempt" ${catFilter === 'privilege_escalation_attempt' ? 'selected' : ''}>Priv Escalation</option>
              <option value="unknown" ${catFilter === 'unknown' ? 'selected' : ''}>Unknown</option>
            </select>
          </div>

          <div class="session-list">
            ${filtered.length === 0 ? `<div style="padding: 1.5rem; text-align: center; color: var(--text-muted);">No matching sessions found.</div>` : filtered.map((s) => `
              <div class="session-item ${s.session_id === (activeSession ? activeSession.session_id : '') ? 'selected' : ''}" onclick="selectSession('${s.session_id}')">
                <div class="session-item-header">
                  <span class="session-id">${escapeHtml(s.session_id)}</span>
                  <span class="score-badge ${getScoreClass(s.analysis.score)}">${s.analysis.score}</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.75rem;">
                  <span class="badge cat-${s.analysis.primary_category}">${s.analysis.primary_category}</span>
                  <span style="color: var(--text-muted); font-family: var(--font-mono);">${s.source_ip || '192.0.2.x'}</span>
                </div>
              </div>
            `).join("")}
          </div>
        </div>

        <!-- Right: Session Detail Pane -->
        <div class="session-detail-pane">
          ${!activeSession ? `<div class="empty-state"><div class="empty-title">Select a Session</div></div>` : `
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.95rem; border-bottom: 1px solid var(--border-subtle); padding-bottom: 0.75rem;">
              <div>
                <h3 style="font-size: 1.05rem; font-family: var(--font-mono); font-weight: 700; color: var(--accent-copper);">
                  Session: ${escapeHtml(activeSession.session_id)}
                </h3>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.2rem;">
                  Source IP: <span style="font-family: var(--font-mono); color: var(--text-secondary);">${escapeHtml(activeSession.source_ip || 'unknown')}</span> |
                  Events: <span style="color: var(--text-secondary); font-family: var(--font-mono);">${activeSession.event_count}</span>
                </div>
              </div>
              <div style="text-align: right;">
                <span class="score-badge ${getScoreClass(activeSession.analysis.score)}" style="font-size: 0.85rem; padding: 0.2rem 0.55rem;">
                  Score: ${activeSession.analysis.score}/100
                </span>
                <div style="margin-top: 0.25rem;"><span class="badge cat-${activeSession.analysis.primary_category}">${activeSession.analysis.primary_category}</span></div>
              </div>
            </div>

            <!-- Findings Section -->
            <div style="margin-bottom: 0.95rem;">
              <h4 style="font-size: 0.78rem; font-weight: 600; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 0.4rem; letter-spacing: 0.04em;">
                Behaviour Findings (${activeSession.analysis.findings.length})
              </h4>
              <div style="display: flex; flex-direction: column; gap: 0.4rem;">
                ${activeSession.analysis.findings.map((f) => `
                  <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 0.55rem 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.2rem;">
                      <span style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 600; color: var(--accent-copper);">${escapeHtml(f.rule_id)}</span>
                      <span class="badge badge-${f.evidence_strength ? f.evidence_strength.toLowerCase() : 'weak'}">${f.evidence_strength}</span>
                    </div>
                    <div style="font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(f.evidence)}</div>
                  </div>
                `).join("")}
              </div>
            </div>

            <!-- Deception Decision -->
            <div class="deception-banner">
              <div class="deception-banner-header">
                <span style="font-weight: 600; font-size: 0.8rem; color: var(--accent-emerald);">
                  &#128737; Adaptive Deception Policy Response
                </span>
                <span class="badge badge-${activeSession.deception.status === 'accepted' ? 'accepted' : 'noop'}">${activeSession.deception.status}</span>
              </div>
              <div style="font-size: 0.8rem; margin-bottom: 0.4rem;">
                <strong>Policy Fired:</strong> <span style="font-family: var(--font-mono);">${activeSession.deception.policy_id}</span><br>
                <strong>Approved Action:</strong> <span style="font-family: var(--font-mono); color: var(--accent-emerald); font-weight: 600;">${activeSession.deception.action.action_id}</span>
                ${activeSession.deception.action.target ? `(Target: <span style="font-family: var(--font-mono);">${escapeHtml(activeSession.deception.action.target)}</span>)` : ''}
              </div>
              <div style="font-size: 0.78rem; color: var(--text-secondary); margin-bottom: 0.4rem;">
                ${escapeHtml(activeSession.deception.explanation)}
              </div>
              ${activeSession.deception.state_change_applied ? `
                <div style="font-size: 0.72rem; background: var(--bg-primary); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 0.4rem; font-family: var(--font-mono); color: var(--text-muted);">
                  State Transition: ${escapeHtml(JSON.stringify(activeSession.deception.state_change_applied))}
                </div>
              ` : ''}
            </div>
          `}
        </div>
      </div>
    `;

    // Attach search and filter event listeners
    const searchInput = document.getElementById("sessionSearchInput");
    if (searchInput) {
      searchInput.addEventListener("input", (e) => {
        state.searchQuery = e.target.value;
        renderSessionExplorer();
      });
    }

    const catSelect = document.getElementById("catFilterSelect");
    if (catSelect) {
      catSelect.addEventListener("change", (e) => {
        state.selectedCategory = e.target.value;
        renderSessionExplorer();
      });
    }
  }

  // --- 3. Attack Graph & Timeline ---
  function renderAttackGraph() {
    const container = document.getElementById("graphContainer");
    if (!container) return;

    if (!state.data || !state.data.loaded || !state.data.sessions.length) {
      container.innerHTML = `
        <div class="empty-state" style="padding-top: 8rem;">
          <div class="empty-icon">&#128392;</div>
          <div class="empty-title">Graph Visualization Standby</div>
          <div class="empty-desc">Load a synthetic scenario to render the interactive session-to-deception relationship graph.</div>
        </div>
      `;
      return;
    }

    const sessions = state.data.sessions;

    // Build Nodes & Links
    // 3 Columns: Left: Sessions, Middle: Behavior Findings, Right: Deception Actions
    const nodes = [];
    const links = [];

    const sessionSpacing = 480 / Math.max(sessions.length, 1);
    const leftX = 140;
    const midX = 460;
    const rightX = 780;

    let findingY = 60;
    let actionY = 60;

    sessions.forEach((s, idx) => {
      const sY = 60 + idx * Math.min(sessionSpacing, 80);
      const sNode = {
        id: s.session_id,
        label: s.session_id,
        sub: s.analysis.primary_category,
        x: leftX,
        y: sY,
        type: "session",
        color: "#C77D4A",
      };
      nodes.push(sNode);

      // Unique findings for this session
      s.analysis.findings.slice(0, 2).forEach((f) => {
        const fId = `${s.session_id}-${f.rule_id}`;
        const fNode = {
          id: fId,
          label: f.rule_id,
          sub: f.category,
          x: midX,
          y: findingY,
          type: "finding",
          color: "#D9A441",
        };
        nodes.push(fNode);
        links.push({ from: sNode, to: fNode });
        findingY += 50;
      });

      // Deception Action
      const aId = `${s.session_id}-act`;
      const aNode = {
        id: aId,
        label: s.deception.action.action_id,
        sub: s.deception.action.target || "no_op",
        x: rightX,
        y: actionY,
        type: "action",
        color: "#78A88B",
      };
      nodes.push(aNode);
      links.push({ from: sNode, to: aNode });
      actionY += 60;
    });

    const svgHeight = Math.max(findingY, actionY, 360);

    container.innerHTML = `
      <div class="graph-controls">
        <button class="graph-btn" title="Zoom In" onclick="zoomGraph(0.15)">+</button>
        <button class="graph-btn" title="Zoom Out" onclick="zoomGraph(-0.15)">-</button>
        <button class="graph-btn" title="Reset Graph" onclick="resetGraph()">&#8634;</button>
      </div>
      <svg class="graph-svg" id="attackGraphSvg" viewBox="0 0 960 ${svgHeight}">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#525247"/>
          </marker>
        </defs>
        <g id="graphTransformGroup" transform="translate(${state.graphPan.x}, ${state.graphPan.y}) scale(${state.graphZoom})">
          <!-- Links -->
          ${links.map((l) => {
            const dx = l.to.x - l.from.x;
            const dy = l.to.y - l.from.y;
            const cx1 = l.from.x + dx * 0.5;
            const cy1 = l.from.y;
            const cx2 = l.from.x + dx * 0.5;
            const cy2 = l.to.y;
            return `
              <path d="M ${l.from.x} ${l.from.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${l.to.x} ${l.to.y}"
                    fill="none" stroke="#414139" stroke-width="1.6" marker-end="url(#arrow)" />
            `;
          }).join("")}

          <!-- Nodes -->
          ${nodes.map((n) => `
            <g transform="translate(${n.x}, ${n.y})" style="cursor: pointer;" onclick="inspectGraphNode('${n.id}', '${n.type}')">
              <rect x="-65" y="-18" width="130" height="36" rx="4" fill="#22231F" stroke="${n.color}" stroke-width="1.4" />
              <text x="0" y="-2" text-anchor="middle" fill="#F2EBDD" font-size="11" font-weight="600" font-family="'JetBrains Mono', monospace">${escapeHtml(n.label)}</text>
              <text x="0" y="11" text-anchor="middle" fill="${n.color}" font-size="8.5" font-weight="500">${escapeHtml(truncate(n.sub, 18))}</text>
            </g>
          `).join("")}
        </g>
      </svg>
    `;

    setupGraphPanZoom();
  }

  function setupGraphPanZoom() {
    const svg = document.getElementById("attackGraphSvg");
    if (!svg) return;

    svg.addEventListener("mousedown", (e) => {
      state.isDraggingGraph = true;
      state.dragStart = { x: e.clientX - state.graphPan.x, y: e.clientY - state.graphPan.y };
    });

    window.addEventListener("mousemove", (e) => {
      if (!state.isDraggingGraph) return;
      state.graphPan.x = e.clientX - state.dragStart.x;
      state.graphPan.y = e.clientY - state.dragStart.y;
      updateGraphTransform();
    });

    window.addEventListener("mouseup", () => {
      state.isDraggingGraph = false;
    });

    svg.addEventListener("wheel", (e) => {
      e.preventDefault();
      const delta = e.deltaY > 0 ? -0.1 : 0.1;
      state.graphZoom = Math.max(0.4, Math.min(2.5, state.graphZoom + delta));
      updateGraphTransform();
    });
  }

  function updateGraphTransform() {
    const g = document.getElementById("graphTransformGroup");
    if (g) {
      g.setAttribute("transform", `translate(${state.graphPan.x}, ${state.graphPan.y}) scale(${state.graphZoom})`);
    }
  }

  window.zoomGraph = (delta) => {
    state.graphZoom = Math.max(0.4, Math.min(2.5, state.graphZoom + delta));
    updateGraphTransform();
  };

  window.resetGraph = () => {
    state.graphZoom = 1;
    state.graphPan = { x: 0, y: 0 };
    updateGraphTransform();
  };

  window.inspectGraphNode = (id, type) => {
    if (type === "session") {
      selectSession(id);
      switchTab("sessions");
    } else {
      showToast(`Node ${id} (${type}) selected.`, "info");
    }
  };

  // --- 4. Chronological Timeline ---
  function renderTimeline() {
    const container = document.getElementById("timelineContent");
    if (!container) return;

    if (!state.data || !state.data.loaded || !state.data.sessions.length) {
      container.innerHTML = `<div class="empty-state"><div class="empty-desc">No session timeline available.</div></div>`;
      return;
    }

    const sessions = state.data.sessions;
    container.innerHTML = `
      <div class="timeline">
        ${sessions.map((s, idx) => `
          <div class="timeline-item">
            <div class="timeline-dot"></div>
            <div class="timeline-content">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
                <span style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-copper); font-size: 0.82rem;">
                  Session #${idx + 1}: ${escapeHtml(s.session_id)}
                </span>
                <span class="badge cat-${s.analysis.primary_category}">${s.analysis.primary_category}</span>
              </div>
              <div style="font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 0.35rem;">
                Source IP: <span style="font-family: var(--font-mono);">${escapeHtml(s.source_ip || '192.0.2.x')}</span> |
                Threat Score: <span style="font-weight: 600; color: var(--accent-amber); font-family: var(--font-mono);">${s.analysis.score}/100</span>
              </div>
              <div style="font-size: 0.75rem; background: var(--bg-secondary); padding: 0.35rem 0.55rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                <strong>Deception Defense:</strong> ${s.deception.policy_id} &rarr;
                <span style="color: var(--accent-emerald); font-weight: 600; font-family: var(--font-mono);">${s.deception.action.action_id}</span>
                ${s.deception.action.target ? `(${escapeHtml(s.deception.action.target)})` : ''}
              </div>
            </div>
          </div>
        `).join("")}
      </div>
    `;
  }

  // --- 5. Behaviour Analysis View ---
  function renderBehaviourAnalysis() {
    const container = document.getElementById("pane-behaviour");
    if (!state.data || !state.data.loaded) {
      container.innerHTML = `<div class="empty-state card"><div class="empty-title">No Behaviour Findings</div><div class="empty-desc">Load a synthetic scenario to inspect findings and scoring.</div></div>`;
      return;
    }

    const { sessions } = state.data;
    const allFindings = [];
    sessions.forEach((s) => {
      s.analysis.findings.forEach((f) => {
        allFindings.push({ ...f, session_id: s.session_id, score: s.analysis.score });
      });
    });

    container.innerHTML = `
      <div style="background: var(--bg-surface); border: 1px solid var(--border-default); border-radius: var(--radius-sm); padding: 0.75rem 1rem; margin-bottom: 0.95rem;">
        <div style="display: flex; align-items: center; gap: 0.4rem; font-weight: 600; color: var(--accent-copper); margin-bottom: 0.2rem; font-size: 0.82rem;">
          &#9432; Deterministic Heuristic Scoring Model
        </div>
        <p style="font-size: 0.78rem; color: var(--text-secondary); line-height: 1.4;">
          The threat score (0–100) is a deterministic indicator calibrated against observable telemetry patterns (recon commands, brute-force iterations, credential commands).
          It provides explainable triage without relying on opaque machine learning probabilities or external cloud models.
        </p>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">&#128269; Aggregated Findings Matrix</div>
          <span class="card-badge">${allFindings.length} Total Findings</span>
        </div>
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Category</th>
                <th>Confidence</th>
                <th>Evidence Explanation</th>
                <th>Triggering Session</th>
              </tr>
            </thead>
            <tbody>
              ${allFindings.map((f) => `
                <tr>
                  <td style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-copper);">${escapeHtml(f.rule_id)}</td>
                  <td><span class="badge cat-${f.category}">${f.category}</span></td>
                  <td><span class="badge badge-${f.evidence_strength ? f.evidence_strength.toLowerCase() : 'weak'}">${f.evidence_strength}</span></td>
                  <td style="font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(f.evidence)}</td>
                  <td style="font-family: var(--font-mono); font-size: 0.75rem; cursor: pointer; color: var(--accent-copper); text-decoration: underline;" onclick="selectSession('${f.session_id}'); switchTab('sessions');">
                    ${escapeHtml(f.session_id)}
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // --- 6. Deception Planner View ---
  function renderDeceptionPlanner() {
    const container = document.getElementById("pane-deception");
    if (!state.data || !state.data.loaded) {
      container.innerHTML = `<div class="empty-state card"><div class="empty-title">Simulated World State Inactive</div><div class="empty-desc">Run a scenario to inspect the fictional honeypot environment and applied deception transitions.</div></div>`;
      return;
    }

    const ws = state.data.world_state;
    const host = ws.host || {};
    const decoyFiles = Object.values(ws.decoy_files || {});
    const services = Object.values(ws.services || {});
    const history = ws.action_history || [];

    const isLive = state.data.source === "live_cowrie";

    container.innerHTML = `
      ${isLive ? `
        <div style="background: var(--bg-surface); border: 1px solid var(--accent-amber-border); border-radius: var(--radius-sm); padding: 0.75rem 0.95rem; margin-bottom: 0.95rem;">
          <div style="display: flex; align-items: center; justify-content: space-between;">
            <div style="font-weight: 600; color: var(--accent-amber); display: flex; align-items: center; gap: 0.35rem; font-size: 0.8rem;">
              &#9888; Live Honeypot Safety Boundary &bull; Simulated Advisory Recommendations Only
            </div>
            <span class="badge" style="background: var(--accent-amber-tint); color: var(--accent-amber); border: 1px solid var(--accent-amber-border); font-size: 0.65rem; font-weight: 600;">ADVISORY ONLY</span>
          </div>
          <p style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.25rem;">
            Phase 7 operates strictly read-only. The deception engine evaluates live sessions and generates recommendations, but never writes decoys, modifies filesystem assets, or executes commands against real attackers or the Cowrie honeypot.
          </p>
        </div>
      ` : ''}
      <div style="background: var(--bg-surface); border: 1px solid var(--accent-emerald-border); border-radius: var(--radius-sm); padding: 0.75rem 0.95rem; margin-bottom: 0.95rem;">
        <div style="display: flex; align-items: center; justify-content: space-between;">
          <div style="font-weight: 600; color: var(--accent-emerald); display: flex; align-items: center; gap: 0.35rem; font-size: 0.8rem;">
            &#128737; Isolated Simulated World State
          </div>
          <span class="safety-pill">&#10004; Zero Host OS Execution</span>
        </div>
        <p style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.25rem;">
          All decoys, services, and accounts are in-memory synthetic assets. No real host filesystem files or network services are created or modified.
        </p>
      </div>

      <!-- Host Identity Card -->
      <div class="card" style="margin-bottom: 0.95rem;">
        <div class="card-header">
          <div class="card-title">&#128421; Simulated Host Identity</div>
          <span class="card-badge">${escapeHtml(host.hostname || 'corp-srv-db01')}</span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.65rem; font-size: 0.78rem;">
          <div><span style="color: var(--text-muted);">OS Distribution:</span><br><strong>${escapeHtml(host.os_name || 'Ubuntu 22.04 LTS')}</strong></div>
          <div><span style="color: var(--text-muted);">Kernel:</span><br><code style="font-family: var(--font-mono);">${escapeHtml(host.kernel || '5.15.0-88')}</code></div>
          <div><span style="color: var(--text-muted);">Architecture:</span><br><strong>${escapeHtml(host.architecture || 'x86_64')}</strong></div>
          <div><span style="color: var(--text-muted);">Primary RFC IP:</span><br><code style="font-family: var(--font-mono);">${escapeHtml(host.primary_ip || '192.0.2.10')}</code></div>
          <div><span style="color: var(--text-muted);">Simulated Uptime:</span><br><strong>${Math.round((host.uptime_seconds || 1843200) / 86400)} days</strong></div>
        </div>
      </div>

      <div class="grid-2col">
        <!-- Decoy Files -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">&#128196; Fictional Decoy Files</div>
            <span class="card-badge">${decoyFiles.filter(d => d.is_visible).length}/${decoyFiles.length} Visible</span>
          </div>
          <div class="table-wrapper">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Type</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                ${decoyFiles.map((d) => `
                  <tr>
                    <td style="font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(d.path)}</td>
                    <td style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(d.file_type)}</td>
                    <td>
                      <span class="badge ${d.is_visible ? 'badge-accepted' : 'badge-noop'}">
                        ${d.is_visible ? 'VISIBLE (DEPLOYED)' : 'STANDBY (HIDDEN)'}
                      </span>
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>

        <!-- Simulated Services -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">&#127760; Simulated Services</div>
            <span class="card-badge">${services.length} Total</span>
          </div>
          <div class="table-wrapper">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Service</th>
                  <th>Port</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                ${services.map((s) => `
                  <tr>
                    <td style="font-weight: 600;">${escapeHtml(s.name)}</td>
                    <td style="font-family: var(--font-mono); font-size: 0.75rem;">${s.port}/${s.protocol}</td>
                    <td>
                      <span class="badge ${s.state === 'active' || s.state === 'revealed' ? 'badge-accepted' : 'badge-noop'}">
                        ${escapeHtml(s.state.toUpperCase())}
                      </span>
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Action History Audit -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">&#128220; ${isLive ? 'Deception Recommendations Audit Trail (Simulated)' : 'Deception Action Audit Trail'}</div>
          <span class="card-badge">${history.length} ${isLive ? 'Recommendations' : 'Actions'}</span>
        </div>
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th>Action ID</th>
                <th>Target</th>
                <th>Explanation</th>
              </tr>
            </thead>
            <tbody>
              ${history.length === 0 ? `<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No actions recorded yet.</td></tr>` : history.map((a) => `
                <tr>
                  <td style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-copper);">${escapeHtml(a.action_id)}</td>
                  <td style="font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(a.target || 'none')}</td>
                  <td style="font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(a.explanation)}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // --- 7. Reports & Warnings View ---
  function renderReports() {
    const container = document.getElementById("pane-reports");
    if (!state.data || !state.data.loaded) {
      container.innerHTML = `<div class="empty-state card"><div class="empty-title">No Diagnostics Available</div><div class="empty-desc">Run a scenario to inspect parser diagnostics and evaluation reports.</div></div>`;
      return;
    }

    const { warnings, warnings_count, events_parsed, input_file, pipeline_version } = state.data;

    container.innerHTML = `
      <div class="grid-2col">
        <div class="card">
          <div class="card-header">
            <div class="card-title">&#128300; Parser Diagnostics</div>
            <span class="card-badge">${warnings_count} Warning(s)</span>
          </div>
          <div style="font-size: 0.85rem; line-height: 1.6; color: var(--text-secondary);">
            <strong>Input Fixture:</strong> <code style="font-family: var(--font-mono); font-size: 0.78rem;">${escapeHtml(input_file)}</code><br>
            <strong>Pipeline Engine:</strong> v${escapeHtml(pipeline_version)}<br>
            <strong>Valid Telemetry Events:</strong> ${events_parsed}<br>
            <strong>Recoverable Line Issues:</strong> ${warnings_count}<br>
            <strong>Parser Health Status:</strong> <span style="color: var(--accent-emerald); font-weight: 600;">Operational (Tolerant Mode)</span>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div class="card-title">&#128229; Export & Artifacts</div>
          </div>
          <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
            Download the sanitized offline analysis, threat findings, and deception state transitions in standardized JSON format.
          </p>
          <button class="btn btn-secondary" onclick="window.location.href='/api/export'">
            Download Sanitized JSON Report
          </button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">&#9888; Parser Warnings Log</div>
          <span class="card-badge">${warnings.length} Recorded</span>
        </div>
        <div class="table-wrapper">
          <table class="data-table">
            <thead>
              <tr>
                <th style="width: 100px;">Line #</th>
                <th>Diagnostic Reason</th>
                <th>Impact</th>
              </tr>
            </thead>
            <tbody>
              ${warnings.length === 0 ? `<tr><td colspan="3" style="text-align: center; color: var(--accent-emerald); padding: 1.5rem;">&#10004; Zero parser warnings. Input fixture strictly valid.</td></tr>` : warnings.map((w) => `
                <tr>
                  <td style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-amber);">Line ${w.line_number}</td>
                  <td style="font-family: var(--font-mono); font-size: 0.82rem; color: var(--accent-rose);">${escapeHtml(w.reason)}</td>
                  <td style="font-size: 0.8rem; color: var(--text-muted);">Line skipped cleanly; parsing resumed without session loss.</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // =========================================================================
  // Helper Functions
  // =========================================================================

  window.selectSession = (sessionId) => {
    state.selectedSessionId = sessionId;
    renderSessionExplorer();
  };

  window.switchTab = (tabName) => {
    els.navTabs.forEach((t) => t.classList.toggle("active", t.dataset.tab === tabName));
    els.tabPanes.forEach((p) => p.classList.toggle("active", p.id === `pane-${tabName}`));
  };

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function truncate(str, maxLen) {
    if (!str) return "";
    return str.length > maxLen ? str.substring(0, maxLen - 2) + "..." : str;
  }

  function getScoreClass(score) {
    if (score <= 25) return "score-low";
    if (score <= 70) return "score-med";
    return "score-high";
  }

  function showToast(message, type = "info") {
    const toast = document.createElement("div");
    toast.className = "toast";
    let icon = "&#9432;";
    if (type === "success") icon = "&#10004;";
    if (type === "error") icon = "&#9888;";
    if (type === "warning") icon = "&#9888;";

    toast.innerHTML = `<span style="color: ${type === 'error' ? 'var(--accent-rose)' : type === 'success' ? 'var(--accent-emerald)' : 'var(--accent-copper)'}; font-size: 1.05rem;">${icon}</span><span>${escapeHtml(message)}</span>`;
    els.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transition = "opacity 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  // =========================================================================
  // Event Bindings & Initialization
  // =========================================================================

  function init() {
    // Tab switching
    els.navTabs.forEach((tab) => {
      tab.addEventListener("click", () => switchTab(tab.dataset.tab));
    });

    // Control bar buttons
    if (els.sourceSelect) {
      els.sourceSelect.addEventListener("change", handleSourceChange);
    }
    if (els.btnRefresh) {
      els.btnRefresh.addEventListener("click", handleRefresh);
    }
    if (els.btnRunScenario) {
      els.btnRunScenario.addEventListener("click", handleRunScenario);
    }
    if (els.btnResetState) {
      els.btnResetState.addEventListener("click", handleResetState);
    }
    if (els.btnExport) {
      els.btnExport.addEventListener("click", handleExport);
    }

    // Initial load
    fetchScenarios();
    fetchCurrentState();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
