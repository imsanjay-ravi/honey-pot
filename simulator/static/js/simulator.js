/**
 * Linux Attacker Simulator — Interactive Client Application
 * Hacker Terminal / Cyber-Ops Console Interface
 */

(() => {
  "use strict";

  const state = {
    sessionId: null,
    history: [],
    historyIndex: -1,
    events: [],
    isRunning: false,
  };

  const els = {
    terminalBody: document.getElementById("terminalBody"),
    terminalOutput: document.getElementById("terminalOutput"),
    terminalInput: document.getElementById("terminalInput"),
    sessionIdDisplay: document.getElementById("sessionIdDisplay"),
    simStatusPill: document.getElementById("simStatusPill"),
    simStatusText: document.getElementById("simStatusText"),
    btnNewSession: document.getElementById("btnNewSession"),
    btnResetSession: document.getElementById("btnResetSession"),
    btnClearTerminal: document.getElementById("btnClearTerminal"),
    threatScoreDisplay: document.getElementById("threatScoreDisplay"),
    categoryDisplay: document.getElementById("categoryDisplay"),
    findingsDisplay: document.getElementById("findingsDisplay"),
    findingsCountBadge: document.getElementById("findingsCountBadge"),
    policyDisplay: document.getElementById("policyDisplay"),
    actionDisplay: document.getElementById("actionDisplay"),
    stateAppliedDisplay: document.getElementById("stateAppliedDisplay"),
    eventsLog: document.getElementById("eventsLog"),
    actionButtons: document.querySelectorAll(".btn-action"),
    chips: document.querySelectorAll(".chip"),
  };

  function setSimulatorStatus(status, label) {
    if (!els.simStatusPill || !els.simStatusText) return;
    els.simStatusPill.className = `status-pill status-${status}`;
    els.simStatusText.textContent = label;
  }

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
    if (!command && output && (output.startsWith("Connected") || output.startsWith("---") || output.startsWith("AI Adaptive"))) {
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
        cmdEl.innerHTML = `<span style="color: var(--info-cyan); font-weight: 700;">[PLAYBOOK ACTION]</span> <span>${escapeHtml(command)}</span>`;
      } else {
        cmdEl.innerHTML = `<span style="color: var(--term-green); font-weight: 700;">root@attacker-vm:~#</span> <span>${escapeHtml(command)}</span>`;
      }
      block.appendChild(cmdEl);
    }

    if (output) {
      const outEl = document.createElement("div");
      outEl.className = "term-out";

      // Highlight security-sensitive words in output
      if (output.includes("Permission denied") || output.includes("Error:") || output.includes("not supported")) {
        outEl.style.color = "var(--alert-red)";
      } else if (output.includes("id_rsa_backup") || output.includes("SYNTHETIC_DECOY") || output.includes("saved")) {
        outEl.style.color = "var(--warn-amber)";
      }

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
      if (els.sessionIdDisplay) {
        els.sessionIdDisplay.textContent = data.session_id;
      }
    }

    const analysis = data.analysis || {};
    const deception = data.deception || {};

    // Threat Score
    const score = typeof analysis.score === "number" ? analysis.score : 0;
    if (els.threatScoreDisplay) {
      els.threatScoreDisplay.textContent = `${score} / 100`;
      els.threatScoreDisplay.className = `score-pill ${score > 70 ? 'score-high' : score > 25 ? 'score-med' : 'score-low'}`;
    }

    // Primary Category
    const cat = analysis.primary_category || "unknown";
    if (els.categoryDisplay) {
      els.categoryDisplay.textContent = cat;
    }

    // Findings
    const findings = analysis.findings || [];
    if (els.findingsCountBadge) {
      els.findingsCountBadge.textContent = findings.length;
    }

    if (els.findingsDisplay) {
      if (findings.length === 0) {
        els.findingsDisplay.innerHTML = `<div class="finding-empty">No active behavioural findings in this session.</div>`;
      } else {
        els.findingsDisplay.innerHTML = findings.map(f => `
          <div class="finding-item">
            <strong style="color: var(--info-cyan);">[${escapeHtml(f.rule_id)}]</strong>
            <span style="color: var(--text-primary);">${escapeHtml(f.category || '')}</span> &bull;
            <span>${escapeHtml(f.evidence)}</span>
          </div>
        `).join("");
      }
    }

    // Deception Policy & Action
    if (els.policyDisplay) {
      els.policyDisplay.textContent = deception.policy_id || "POL-DEFAULT-NOOP";
    }

    if (els.actionDisplay) {
      const action = deception.action || {};
      const status = deception.status || 'no_op';
      els.actionDisplay.innerHTML = `
        <span style="color: var(--term-green); font-weight: 700;">${escapeHtml(action.action_id || 'no_op')}</span>
        ${action.target ? `<span style="color: var(--text-muted); font-size: 0.7rem;">(${escapeHtml(action.target)})</span>` : ''}
        <span class="badge ${status === 'accepted' ? 'badge-accepted' : 'badge-noop'}">${escapeHtml(status)}</span>
      `;
    }

    // State Change Applied
    if (els.stateAppliedDisplay) {
      const stateApplied = deception.state_change_applied;
      if (stateApplied && Object.keys(stateApplied).length > 0) {
        els.stateAppliedDisplay.innerHTML = `<pre class="json-state-box">${escapeHtml(JSON.stringify(stateApplied, null, 2))}</pre>`;
      } else {
        els.stateAppliedDisplay.innerHTML = `<span class="state-none">None (baseline state)</span>`;
      }
    }

    // Events Log
    if (data.event) {
      state.events.unshift(data.event);
      renderEventsLog();
    }
  }

  function renderEventsLog() {
    if (!els.eventsLog) return;

    if (state.events.length === 0) {
      els.eventsLog.innerHTML = `<div class="finding-empty">No events generated yet. Run a command or playbook.</div>`;
      return;
    }

    els.eventsLog.innerHTML = state.events.slice(0, 12).map((e) => {
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
    if (!trimmed || state.isRunning) return;

    state.isRunning = true;
    setSimulatorStatus("running", "EXECUTING...");

    state.history.push(trimmed);
    state.historyIndex = state.history.length;
    els.terminalInput.value = "";

    try {
      const res = await apiPost("/api/simulator/command", { command: trimmed });
      appendTerminal(trimmed, res.terminal_output, false);
      updateTelemetry(res);
    } catch (err) {
      appendTerminal(trimmed, `Error: ${err.message}`, false);
    } finally {
      state.isRunning = false;
      setSimulatorStatus("ready", "READY");
      els.terminalInput.focus();
    }
  }

  async function handleActionClick(actionName) {
    if (state.isRunning) return;
    state.isRunning = true;

    setSimulatorStatus("running", `SIMULATING: ${actionName.toUpperCase()}`);
    els.actionButtons.forEach(b => (b.disabled = true));

    try {
      appendTerminal(`Simulating Attack Scenario: ${actionName}`, "Dispatching scenario events through pipeline...", true);
      const res = await apiPost("/api/simulator/action", { action: actionName });
      appendTerminal(`Execution Complete: ${actionName}`, res.terminal_output, true);
      updateTelemetry(res);
    } catch (err) {
      appendTerminal(actionName, `Action Error: ${err.message}`, true);
    } finally {
      state.isRunning = false;
      setSimulatorStatus("ready", "READY");
      els.actionButtons.forEach(b => (b.disabled = false));
      els.terminalInput.focus();
    }
  }

  async function init() {
    try {
      const stateData = await apiGet("/api/simulator/state");
      state.sessionId = stateData.session_id;
      if (els.sessionIdDisplay) {
        els.sessionIdDisplay.textContent = stateData.session_id;
      }
      state.events = (stateData.events || []).reverse();
      renderEventsLog();
      updateTelemetry(stateData);
    } catch (err) {
      console.error("Failed to load initial simulator state:", err);
    }

    appendTerminal(
      "",
      "Connected to simulated Linux honeypot console (corp-srv-db01).\n" +
      "Environment: Fictional In-Memory Sandbox (Safety Boundary Active).\n" +
      "Type 'help' to inspect supported simulation commands or select an Attack Playbook on the left.\n" +
      "-----------------------------------------------------------------------------------------------"
    );

    // Keyboard Handler on Terminal Input
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

    // Action Playbook buttons
    els.actionButtons.forEach(btn => {
      btn.addEventListener("click", () => handleActionClick(btn.dataset.action));
    });

    // Quick Command Chips
    els.chips.forEach(chip => {
      chip.addEventListener("click", () => {
        const cmd = chip.dataset.cmd;
        if (cmd) {
          els.terminalInput.value = cmd;
          handleCommandSubmit(cmd);
        }
      });
    });

    // Clear Terminal button
    els.btnClearTerminal.addEventListener("click", () => {
      els.terminalOutput.innerHTML = "";
      els.terminalInput.focus();
    });

    // New Session button
    els.btnNewSession.addEventListener("click", async () => {
      try {
        const res = await apiPost("/api/simulator/session/new", {});
        state.sessionId = res.session_id;
        if (els.sessionIdDisplay) {
          els.sessionIdDisplay.textContent = res.session_id;
        }
        state.events = [];
        renderEventsLog();
        appendTerminal("", `--- Initialized fresh simulated session: ${res.session_id} ---`);
      } catch (err) {
        appendTerminal("", `Failed to start new session: ${err.message}`);
      }
    });

    // Reset Session button
    els.btnResetSession.addEventListener("click", async () => {
      if (!confirm("Reset simulator session and fictional WorldState to clean baseline?")) return;
      try {
        const res = await apiPost("/api/simulator/reset", {});
        state.sessionId = res.session_id;
        if (els.sessionIdDisplay) {
          els.sessionIdDisplay.textContent = res.session_id;
        }
        state.events = [];
        renderEventsLog();
        els.terminalOutput.innerHTML = "";
        appendTerminal("", `--- Simulator and WorldState reset to clean baseline (${res.session_id}) ---`);
      } catch (err) {
        appendTerminal("", `Failed to reset simulator: ${err.message}`);
      }
    });

    // Focus input when clicking anywhere in terminal body
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
