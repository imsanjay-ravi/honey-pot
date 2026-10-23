/**
 * Linux Attacker Simulator — Interactive Client Application
 */

(() => {
  "use strict";

  const state = {
    sessionId: null,
    history: [],
    historyIndex: -1,
    events: [],
  };

  const els = {
    terminalBody: document.getElementById("terminalBody"),
    terminalOutput: document.getElementById("terminalOutput"),
    terminalInput: document.getElementById("terminalInput"),
    sessionIdDisplay: document.getElementById("sessionIdDisplay"),
    btnNewSession: document.getElementById("btnNewSession"),
    btnResetSession: document.getElementById("btnResetSession"),
    btnClearTerminal: document.getElementById("btnClearTerminal"),
    threatScoreDisplay: document.getElementById("threatScoreDisplay"),
    categoryDisplay: document.getElementById("categoryDisplay"),
    findingsDisplay: document.getElementById("findingsDisplay"),
    policyDisplay: document.getElementById("policyDisplay"),
    actionDisplay: document.getElementById("actionDisplay"),
    stateAppliedDisplay: document.getElementById("stateAppliedDisplay"),
    eventsLog: document.getElementById("eventsLog"),
    actionButtons: document.querySelectorAll(".btn-action"),
  };

  async function apiPost(endpoint, body) {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "API Request failed");
    }
    return await res.json();
  }

  async function apiGet(endpoint) {
    const res = await fetch(endpoint);
    if (!res.ok) throw new Error("API Request failed");
    return await res.json();
  }

  function appendTerminal(command, output, isAction = false) {
    if (!command && output && (output.startsWith("Connected") || output.startsWith("---"))) {
      const banner = document.createElement("div");
      banner.className = "term-banner-block";
      banner.textContent = output;
      els.terminalOutput.appendChild(banner);
      els.terminalBody.scrollTop = els.terminalBody.scrollHeight;
      return;
    }

    const block = document.createElement("div");
    block.className = `term-block ${isAction ? 'action-block' : ''}`;

    if (command) {
      const cmdEl = document.createElement("div");
      cmdEl.className = "term-cmd";
      if (isAction) {
        cmdEl.innerHTML = `<span style="color: #c084fc;">[SCENARIO ACTION]</span> <span>${escapeHtml(command)}</span>`;
      } else {
        cmdEl.innerHTML = `<span style="color: #22c55e;">root@attacker-vm:~#</span> <span>${escapeHtml(command)}</span>`;
      }
      block.appendChild(cmdEl);
    }

    if (output) {
      const outEl = document.createElement("div");
      outEl.className = "term-out";
      outEl.textContent = output;
      block.appendChild(outEl);
    }

    els.terminalOutput.appendChild(block);
    els.terminalBody.scrollTop = els.terminalBody.scrollHeight;
  }

  function updateTelemetry(data) {
    if (!data) return;

    if (data.session_id) {
      state.sessionId = data.session_id;
      els.sessionIdDisplay.textContent = data.session_id;
    }

    const analysis = data.analysis || {};
    const deception = data.deception || {};

    // Threat Score
    const score = analysis.score || 0;
    els.threatScoreDisplay.textContent = `${score}/100`;
    els.threatScoreDisplay.className = `badge ${score > 70 ? 'badge-high' : score > 25 ? 'badge-med' : 'badge-low'}`;

    // Primary Category
    const cat = analysis.primary_category || "unknown";
    els.categoryDisplay.textContent = cat;

    // Findings
    const findings = analysis.findings || [];
    if (findings.length === 0) {
      els.findingsDisplay.innerHTML = `<span style="color: var(--text-muted); font-size: 0.8rem;">No active behavioural findings.</span>`;
    } else {
      els.findingsDisplay.innerHTML = findings.map(f => `
        <div class="finding-item">
          <strong style="color: #38bdf8;">[${escapeHtml(f.rule_id)}]</strong> ${escapeHtml(f.evidence)}
        </div>
      `).join("");
    }

    // Deception Policy & Action
    els.policyDisplay.textContent = deception.policy_id || "POL-DEFAULT-NOOP";
    const action = deception.action || {};
    els.actionDisplay.innerHTML = `
      <span style="color: #22c55e; font-weight: 600;">${escapeHtml(action.action_id || 'no_op')}</span>
      ${action.target ? `<span style="color: var(--text-muted); font-size: 0.75rem;">(${escapeHtml(action.target)})</span>` : ''}
      <span class="badge ${deception.status === 'accepted' ? 'badge-accepted' : 'badge-noop'}">${deception.status || 'no_op'}</span>
    `;

    // State Change Applied
    const stateApplied = deception.state_change_applied;
    if (stateApplied && Object.keys(stateApplied).length > 0) {
      els.stateAppliedDisplay.innerHTML = `<pre class="json-state-box">${escapeHtml(JSON.stringify(stateApplied, null, 2))}</pre>`;
    } else {
      els.stateAppliedDisplay.innerHTML = `<span style="color: var(--text-muted); font-size: 0.78rem;">None (no-op)</span>`;
    }

    // Events Log
    if (data.event) {
      state.events.unshift(data.event);
      renderEventsLog();
    }
  }

  function renderEventsLog() {
    if (state.events.length === 0) {
      els.eventsLog.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem; text-align: center; padding: 1rem;">No events generated yet.</div>`;
      return;
    }

    els.eventsLog.innerHTML = state.events.slice(0, 10).map((e) => {
      const timeStr = e.timestamp ? (e.timestamp.split("T")[1] || "").slice(0, 8) : "";
      const detail = e.command || e.username || e.input || e.event_type || "";
      return `
        <div class="event-log-item">
          <div class="event-log-meta">
            <span class="event-badge">${escapeHtml(e.event_type)}</span>
            <span class="event-time">${escapeHtml(timeStr)}</span>
          </div>
          <div class="event-log-detail">${escapeHtml(detail)}</div>
        </div>
      `;
    }).join("");
  }

  async function handleCommandSubmit(cmd) {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    state.history.push(trimmed);
    state.historyIndex = state.history.length;
    els.terminalInput.value = "";

    try {
      const res = await apiPost("/api/simulator/command", { command: trimmed });
      appendTerminal(trimmed, res.terminal_output, false);
      updateTelemetry(res);
    } catch (err) {
      appendTerminal(trimmed, `Error: ${err.message}`, false);
    }
  }

  async function handleActionClick(actionName) {
    try {
      appendTerminal(`Simulating Attack Scenario: ${actionName}`, "Dispatching scenario events through pipeline...", true);
      const res = await apiPost("/api/simulator/action", { action: actionName });
      appendTerminal(`Execution Complete: ${actionName}`, res.terminal_output, true);
      updateTelemetry(res);
    } catch (err) {
      appendTerminal(actionName, `Action Error: ${err.message}`, true);
    }
  }

  async function init() {
    try {
      const stateData = await apiGet("/api/simulator/state");
      state.sessionId = stateData.session_id;
      els.sessionIdDisplay.textContent = stateData.session_id;
      state.events = (stateData.events || []).reverse();
      renderEventsLog();
      updateTelemetry(stateData);
    } catch (err) {
      console.error("Failed to load initial simulator state:", err);
    }

    appendTerminal("", "Connected to simulated Linux honeypot console.\nType 'help' to view the explicit allowlist of supported simulation commands.\n-------------------------------------------------------------");

    // Enter Key on Terminal Input
    els.terminalInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        handleCommandSubmit(els.terminalInput.value);
      } else if (e.key === "ArrowUp") {
        if (state.historyIndex > 0) {
          state.historyIndex--;
          els.terminalInput.value = state.history[state.historyIndex] || "";
        }
      } else if (e.key === "ArrowDown") {
        if (state.historyIndex < state.history.length - 1) {
          state.historyIndex++;
          els.terminalInput.value = state.history[state.historyIndex] || "";
        } else {
          state.historyIndex = state.history.length;
          els.terminalInput.value = "";
        }
      }
    });

    // Action buttons
    els.actionButtons.forEach(btn => {
      btn.addEventListener("click", () => handleActionClick(btn.dataset.action));
    });

    // Control buttons
    els.btnClearTerminal.addEventListener("click", () => {
      els.terminalOutput.innerHTML = "";
    });

    els.btnNewSession.addEventListener("click", async () => {
      const res = await apiPost("/api/simulator/session/new", {});
      state.sessionId = res.session_id;
      els.sessionIdDisplay.textContent = res.session_id;
      state.events = [];
      renderEventsLog();
      appendTerminal("", `--- Initialized fresh simulated session: ${res.session_id} ---`);
    });

    els.btnResetSession.addEventListener("click", async () => {
      if (!confirm("Reset simulator session and fictional WorldState to baseline?")) return;
      const res = await apiPost("/api/simulator/reset", {});
      state.sessionId = res.session_id;
      els.sessionIdDisplay.textContent = res.session_id;
      state.events = [];
      renderEventsLog();
      els.terminalOutput.innerHTML = "";
      appendTerminal("", `--- Simulator and WorldState reset to clean baseline (${res.session_id}) ---`);
    });

    // Focus terminal input
    els.terminalBody.addEventListener("click", () => els.terminalInput.focus());
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  document.addEventListener("DOMContentLoaded", init);
})();
