# Phase 3 — Event Schema

## Purpose

This document defines the normalized event representation produced by
the Cowrie log parser.

The parser converts Cowrie's raw JSON events into a stable event format
that can be consumed by later components of the adaptive deception system.

## Common Fields

| Field | Type | Description |
|---|---|---|
| timestamp | string | UTC timestamp of the event |
| session_id | string | Identifier of the Cowrie attacker session |
| event_type | string | Normalized event category |
| source_ip | string | Source/attacker IP address |
| destination_ip | string | Honeypot IP address |
| destination_port | integer | Target service port |

## Event Types

### session_connect

Represents a new attacker connection.

### login

Represents an authentication attempt.

Additional fields may include:

- username
- password
- success

### command

Represents a command entered by the attacker.

Additional field:

- command

### session_closed

Represents termination of an attacker session.

## Example

```json
{
  "timestamp": "2026-08-23T21:10:08.545252Z",
  "session_id": "ef5a4ae847a8",
  "event_type": "command",
  "source_ip": "10.10.10.20",
  "destination_ip": "10.10.10.10",
  "destination_port": 2222,
  "command": "uname"
}
