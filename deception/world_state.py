"""
deception/world_state.py — Simulated in-memory fictional world state.

Represents a fictional honeypot environment entirely in memory:
- Fictional host identity and system information.
- Fictional users and services.
- Fictional directories and decoy files.
- Discovered entity tracking (files, services, users).
- Attacker interest profiling.
- History of applied deception actions.
- Sequence of state changes and audit events for dashboard visualization.

SAFETY GUARANTEES:
- Completely in-memory; never touches the real host filesystem.
- Uses strictly fictional data (RFC 5737 IPs, simulated credentials).
- Never executes captured commands or shell processes.
- Fresh state initialization ensures complete isolation across test cases.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Data classes for world state entities
# ---------------------------------------------------------------------------

@dataclass
class HostIdentity:
    """Simulated host identity metadata."""
    hostname: str = "corp-srv-db01"
    os_name: str = "Ubuntu 22.04.3 LTS"
    kernel: str = "5.15.0-88-generic"
    architecture: str = "x86_64"
    uptime_seconds: int = 1843200
    primary_ip: str = "192.0.2.10"

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "kernel": self.kernel,
            "architecture": self.architecture,
            "uptime_seconds": self.uptime_seconds,
            "primary_ip": self.primary_ip,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HostIdentity:
        return cls(
            hostname=data.get("hostname", "corp-srv-db01"),
            os_name=data.get("os_name", "Ubuntu 22.04.3 LTS"),
            kernel=data.get("kernel", "5.15.0-88-generic"),
            architecture=data.get("architecture", "x86_64"),
            uptime_seconds=data.get("uptime_seconds", 1843200),
            primary_ip=data.get("primary_ip", "192.0.2.10"),
        )


@dataclass
class FictionalUser:
    """Simulated user account."""
    username: str
    uid: int
    gid: int
    home_dir: str
    shell: str
    role: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "uid": self.uid,
            "gid": self.gid,
            "home_dir": self.home_dir,
            "shell": self.shell,
            "role": self.role,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FictionalUser:
        return cls(
            username=data["username"],
            uid=data["uid"],
            gid=data["gid"],
            home_dir=data["home_dir"],
            shell=data["shell"],
            role=data["role"],
        )


@dataclass
class FictionalService:
    """Simulated network service."""
    name: str
    port: int
    protocol: str
    state: str  # "active", "hidden", "revealed"
    description: str
    banner: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "description": self.description,
            "banner": self.banner,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FictionalService:
        return cls(
            name=data["name"],
            port=data["port"],
            protocol=data.get("protocol", "tcp"),
            state=data.get("state", "hidden"),
            description=data.get("description", ""),
            banner=data.get("banner", ""),
        )


@dataclass
class DecoyFile:
    """Simulated decoy file entry."""
    path: str
    description: str
    file_type: str
    is_visible: bool
    fake_content: str
    owner: str
    permissions: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "description": self.description,
            "file_type": self.file_type,
            "is_visible": self.is_visible,
            "fake_content": self.fake_content,
            "owner": self.owner,
            "permissions": self.permissions,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DecoyFile:
        return cls(
            path=data["path"],
            description=data.get("description", ""),
            file_type=data.get("file_type", "generic"),
            is_visible=data.get("is_visible", False),
            fake_content=data.get("fake_content", ""),
            owner=data.get("owner", "root"),
            permissions=data.get("permissions", "0644"),
        )


# ---------------------------------------------------------------------------
# Default fictional world configuration
# ---------------------------------------------------------------------------

def _default_users() -> dict[str, FictionalUser]:
    return {
        "root": FictionalUser(
            username="root",
            uid=0,
            gid=0,
            home_dir="/root",
            shell="/bin/bash",
            role="system_admin",
        ),
        "deploy": FictionalUser(
            username="deploy",
            uid=1000,
            gid=1000,
            home_dir="/home/deploy",
            shell="/bin/bash",
            role="deployment_operator",
        ),
        "backup": FictionalUser(
            username="backup",
            uid=1001,
            gid=1001,
            home_dir="/home/backup",
            shell="/bin/bash",
            role="backup_operator",
        ),
        "www-data": FictionalUser(
            username="www-data",
            uid=33,
            gid=33,
            home_dir="/var/www",
            shell="/usr/sbin/nologin",
            role="service_account",
        ),
    }


def _default_services() -> dict[str, FictionalService]:
    return {
        "ssh": FictionalService(
            name="ssh",
            port=22,
            protocol="tcp",
            state="active",
            description="OpenSSH 8.9p1 Ubuntu-3ubuntu0.4",
            banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
        ),
        "http-web": FictionalService(
            name="http-web",
            port=80,
            protocol="tcp",
            state="active",
            description="Nginx HTTP web application proxy",
            banner="nginx/1.18.0 (Ubuntu)",
        ),
        "mysql-backend": FictionalService(
            name="mysql-backend",
            port=3306,
            protocol="tcp",
            state="hidden",
            description="Internal MySQL database service",
            banner="8.0.35-0ubuntu0.22.04.1",
        ),
        "redis-cache": FictionalService(
            name="redis-cache",
            port=6379,
            protocol="tcp",
            state="hidden",
            description="Internal Redis cache store",
            banner="redis_version:7.0.15",
        ),
        "admin-mgmt": FictionalService(
            name="admin-mgmt",
            port=8443,
            protocol="tcp",
            state="hidden",
            description="Internal administrative management gateway",
            banner="AdminGateway/1.2.0-internal",
        ),
    }


def _default_decoy_files() -> dict[str, DecoyFile]:
    return {
        "/root/.ssh/id_rsa_backup": DecoyFile(
            path="/root/.ssh/id_rsa_backup",
            description="Decoy administrative private SSH key",
            file_type="ssh_credential",
            is_visible=False,
            fake_content="-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC_DECOY_KEY_MATERIAL_UNUSABLE\n-----END OPENSSH PRIVATE KEY-----",
            owner="root",
            permissions="0600",
        ),
        "/var/www/internal/.env": DecoyFile(
            path="/var/www/internal/.env",
            description="Decoy application environment file with synthetic credentials",
            file_type="app_secrets",
            is_visible=False,
            fake_content="DB_HOST=127.0.0.1\nDB_USER=fictional_app\nDB_PASS=SynthSecretKey2026!\nAPI_TOKEN=synth_tok_9b7a12",
            owner="www-data",
            permissions="0640",
        ),
        "/home/backup/db_dump.sql": DecoyFile(
            path="/home/backup/db_dump.sql",
            description="Decoy database backup archive containing fictional schema",
            file_type="database_backup",
            is_visible=False,
            fake_content="-- Synthetic Database Backup\nCREATE TABLE app_users (id INT, email VARCHAR(100), pass_hash VARCHAR(64));",
            owner="backup",
            permissions="0644",
        ),
        "/etc/nginx/ssl_admin_key.pem": DecoyFile(
            path="/etc/nginx/ssl_admin_key.pem",
            description="Decoy SSL TLS certificate private key",
            file_type="ssl_certificate",
            is_visible=False,
            fake_content="-----BEGIN PRIVATE KEY-----\nSYNTHETIC_SSL_DECOY_KEY_DATA\n-----END PRIVATE KEY-----",
            owner="root",
            permissions="0600",
        ),
    }


# ---------------------------------------------------------------------------
# Main WorldState class
# ---------------------------------------------------------------------------

class WorldState:
    """
    In-memory representation of the fictional honeypot environment.
    """

    def __init__(
        self,
        host: HostIdentity | None = None,
        users: dict[str, FictionalUser] | None = None,
        services: dict[str, FictionalService] | None = None,
        decoy_files: dict[str, DecoyFile] | None = None,
        discovered_files: set[str] | None = None,
        discovered_services: set[str] | None = None,
        discovered_users: set[str] | None = None,
        attacker_interests: list[str] | None = None,
        action_history: list[dict[str, Any]] | None = None,
        events: list[dict[str, Any]] | None = None,
    ) -> None:
        self.host = host if host is not None else HostIdentity()
        self.users = users if users is not None else _default_users()
        self.services = services if services is not None else _default_services()
        self.decoy_files = decoy_files if decoy_files is not None else _default_decoy_files()

        self.discovered_files = set(discovered_files) if discovered_files is not None else set()
        self.discovered_services = (
            set(discovered_services)
            if discovered_services is not None
            else {"ssh", "http-web"}
        )
        self.discovered_users = set(discovered_users) if discovered_users is not None else {"root"}
        self.attacker_interests = list(attacker_interests) if attacker_interests is not None else []
        self.action_history = list(action_history) if action_history is not None else []
        self.events = list(events) if events is not None else []
        self._next_sequence_id = len(self.events) + 1

    @classmethod
    def create_default(cls) -> WorldState:
        """Create a fresh, completely isolated default world state."""
        return cls()

    def log_event(self, event_type: str, details: dict[str, Any]) -> dict[str, Any]:
        """
        Record a state change or observation event for dashboard visualization.
        """
        ts = datetime.now(timezone.utc).isoformat()
        evt = {
            "sequence_id": self._next_sequence_id,
            "timestamp": ts,
            "event_type": event_type,
            "details": copy.deepcopy(details),
        }
        self._next_sequence_id += 1
        self.events.append(evt)
        return evt

    def is_decoy_visible(self, path: str) -> bool:
        """Check if a decoy file is currently visible/presented."""
        decoy = self.decoy_files.get(path)
        return decoy.is_visible if decoy is not None else False

    def present_decoy(self, path: str) -> bool:
        """
        Make a decoy file visible to the simulated environment.
        Returns True if presented, False if not found or already visible.
        """
        decoy = self.decoy_files.get(path)
        if decoy is None or decoy.is_visible:
            return False
        decoy.is_visible = True
        self.discovered_files.add(path)
        self.log_event("decoy_file_presented", {"path": path, "file_type": decoy.file_type})
        return True

    def is_service_revealed(self, name: str) -> bool:
        """Check if a service has been revealed to the attacker."""
        svc = self.services.get(name)
        if svc is None:
            return False
        return svc.state == "revealed" or name in self.discovered_services

    def reveal_service(self, name: str) -> bool:
        """
        Reveal a hidden service to the attacker.
        Returns True if newly revealed, False if not found or already revealed/active.
        """
        svc = self.services.get(name)
        if svc is None or svc.state == "revealed" or svc.state == "active":
            return False
        svc.state = "revealed"
        self.discovered_services.add(name)
        self.log_event("service_revealed", {"name": name, "port": svc.port, "protocol": svc.protocol})
        return True

    def record_interest(self, interest_topic: str) -> bool:
        """
        Record an observed attacker interest topic.
        Avoids duplicate consecutive entries.
        """
        if not interest_topic or not isinstance(interest_topic, str):
            return False
        if interest_topic not in self.attacker_interests:
            self.attacker_interests.append(interest_topic)
            self.log_event("attacker_interest_recorded", {"topic": interest_topic})
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """
        Return a complete, JSON-serializable representation of the world state.
        """
        return {
            "host": self.host.to_dict(),
            "users": {k: u.to_dict() for k, u in self.users.items()},
            "services": {k: s.to_dict() for k, s in self.services.items()},
            "decoy_files": {k: d.to_dict() for k, d in self.decoy_files.items()},
            "discovered_files": sorted(self.discovered_files),
            "discovered_services": sorted(self.discovered_services),
            "discovered_users": sorted(self.discovered_users),
            "attacker_interests": list(self.attacker_interests),
            "action_history": list(self.action_history),
            "events": list(self.events),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorldState:
        """
        Construct a WorldState instance from a serialized dictionary.
        """
        host = HostIdentity.from_dict(data.get("host", {}))
        users = {
            k: FictionalUser.from_dict(v)
            for k, v in data.get("users", {}).items()
        }
        services = {
            k: FictionalService.from_dict(v)
            for k, v in data.get("services", {}).items()
        }
        decoy_files = {
            k: DecoyFile.from_dict(v)
            for k, v in data.get("decoy_files", {}).items()
        }
        return cls(
            host=host,
            users=users,
            services=services,
            decoy_files=decoy_files,
            discovered_files=set(data.get("discovered_files", [])),
            discovered_services=set(data.get("discovered_services", [])),
            discovered_users=set(data.get("discovered_users", [])),
            attacker_interests=list(data.get("attacker_interests", [])),
            action_history=list(data.get("action_history", [])),
            events=list(data.get("events", [])),
        )
