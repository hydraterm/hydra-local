"""Local Hydra developer client. Uses the existing macOS/Linux daemon protocol.

No app database access, daemon startup, plugin installation, or remote authority.
Input is UTF-8 text sent to a PTY, not an acknowledged provider/API operation.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import closing
from dataclasses import dataclass
import json
import math
import socket
import sys
import time

MAX_LINE_BYTES = 16 * 1024 * 1024  # maestro_protocol::MAX_LINE_BYTES
PROTOCOL_VERSION = 3  # maestro_protocol::DAEMON_PROTOCOL_VERSION


class HydraError(RuntimeError):
    pass


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise HydraError(f"missing or invalid {field}")
    return value


def _timeout(value: float | None) -> float | None:
    if value is not None and (not math.isfinite(value) or value <= 0):
        raise ValueError("timeout must be positive and finite, or None")
    return value


def _invalid_constant(_value: str) -> None:
    raise ValueError("non-finite numbers are not JSON")


class _Connection:
    def __init__(self, endpoint: str, timeout: float):
        self.timeout = _timeout(timeout)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.buffer = bytearray()
        self.deadline = None if timeout is None else time.monotonic() + timeout
        try:
            self.socket.settimeout(self.remaining())
            self.socket.connect(endpoint)
            self.send({"op": "daemon_info"}, self.deadline)
            self.info = self.read(self.remaining())
            if self.info.get("ev") != "daemon_info":
                raise HydraError("endpoint did not return Hydra DaemonInfo")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self.socket.close()

    def remaining(self) -> float | None:
        remaining = None if self.deadline is None else self.deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise TimeoutError("Hydra operation timed out")
        return remaining

    def require_control_protocol(self) -> None:
        version = self.info.get("protocol_version")
        if type(version) is not int or version != PROTOCOL_VERSION:
            raise HydraError(f"control requires daemon protocol {PROTOCOL_VERSION}; got {version!r}")

    def require(self, capability: str) -> None:
        if self.info.get(capability) is not True:
            raise HydraError(f"daemon does not support {capability}; use matching current binaries")

    def send(self, request: dict, deadline: float | None = None) -> None:
        encoded = json.dumps(request, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
        if len(encoded) + 1 > MAX_LINE_BYTES:
            raise HydraError("request exceeds Hydra's wire frame limit; nothing sent")
        remaining = self.timeout if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise TimeoutError("Hydra operation timed out; request not sent")
        self.socket.settimeout(remaining)
        self.socket.sendall(encoded + b"\n")

    def read(self, timeout: float | None) -> dict:
        timeout = _timeout(timeout)
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            end = self.buffer.find(b"\n")
            if end >= 0:
                if end + 1 > MAX_LINE_BYTES:
                    raise HydraError("daemon frame exceeds Hydra's wire limit")
                line = bytes(self.buffer[:end])
                del self.buffer[:end + 1]
                try:
                    event = json.loads(line, parse_constant=_invalid_constant)
                except (ValueError, UnicodeError) as error:
                    raise HydraError("daemon returned invalid JSON") from error
                if not isinstance(event, dict) or not isinstance(event.get("ev"), str):
                    raise HydraError("daemon returned an invalid event")
                if event["ev"] == "error":
                    raise HydraError(str(event.get("message", "daemon refused operation")))
                return event
            if len(self.buffer) > MAX_LINE_BYTES:
                raise HydraError("daemon frame exceeds Hydra's wire limit")
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise TimeoutError("Hydra response timed out")
            self.socket.settimeout(remaining)
            chunk = self.socket.recv(min(65536, MAX_LINE_BYTES + 1 - len(self.buffer)))
            if not chunk:
                raise HydraError("daemon disconnected; pending input delivery is unknown")
            self.buffer.extend(chunk)


@dataclass(frozen=True)
class SessionRef:
    id: str
    generation: str
    daemon_instance_id: str


class Hydra:
    """Control queries use separate connections, so they cannot consume stream events."""

    def __init__(self, endpoint: str, timeout: float = 5.0):
        self.endpoint = endpoint
        self.timeout = _timeout(timeout)

    def _connect(self) -> _Connection:
        return _Connection(self.endpoint, self.timeout)

    def info(self) -> dict:
        with closing(self._connect()) as connection:
            return connection.info

    def sessions(self) -> list[SessionRef]:
        with closing(self._connect()) as connection:
            instance = _string(connection.info.get("daemon_instance_id"), "daemon identity")
            connection.send({"op": "list_sessions"}, connection.deadline)
            event = connection.read(connection.remaining())
            rows = event.get("sessions")
            # The daemon omits its empty metadata vector, but always sends legacy ids.
            if "sessions" not in event and event.get("ids") == []:
                rows = []
            if event.get("ev") != "sessions" or not isinstance(rows, list):
                raise HydraError("daemon does not expose generation-bearing session listings")
            if any(not isinstance(row, dict) for row in rows):
                raise HydraError("daemon returned an invalid session listing")
            return [SessionRef(_string(row.get("id"), "session id"),
                               _string(row.get("generation"), "session generation"), instance)
                    for row in rows]

    def attach(self, session: SessionRef, *, raw_output: bool = False) -> SessionStream:
        connection = self._connect()
        try:
            connection.require_control_protocol()
            connection.require("generation_conditional_attach")
            connection.require("output_generation_echo")
            if connection.info.get("daemon_instance_id") != session.daemon_instance_id:
                raise HydraError("daemon changed; list sessions again before choosing a target")
            connection.send({"op": "attach", "id": session.id,
                             "expected_session_generation": session.generation,
                             "output_generation": 1, "want_raw_output": raw_output}, connection.deadline)
            initial = connection.read(connection.remaining())
            if initial.get("ev") == "session_attach_refused":
                raise HydraError(f"attach refused: {initial.get('reason', 'unknown reason')}")
            if (initial.get("ev") != "grid" or initial.get("id") != session.id
                    or type(initial.get("output_generation")) is not int
                    or initial["output_generation"] != 1
                    or not isinstance(initial.get("grid"), dict)
                    or initial["grid"].get("generation") != session.generation):
                raise HydraError("attach did not prove the selected session lifetime")
            return SessionStream(connection, session, initial)
        except BaseException:
            connection.close()
            raise


class SessionStream:
    def __init__(self, connection: _Connection, session: SessionRef, initial: dict):
        self._connection = connection
        self.session = session
        self.initial = initial

    def __enter__(self) -> SessionStream:
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def close(self) -> None:
        # Connection close releases only this attachment. No Kill or daemon shutdown.
        self._connection.close()

    def send_text(self, text: str) -> dict:
        """No success ACK exists. Never automatically retry an ambiguous write."""
        if not isinstance(text, str):
            raise TypeError("input must be UTF-8 text")
        self._connection.require("generation_conditional_mutations")
        try:
            self._connection.send({"op": "write", "id": self.session.id,
                                   "expected_generation": self.session.generation, "data": text})
        except OSError as error:
            raise HydraError(
                "connection failed; input delivery is unknown; do not blindly retry"
            ) from error
        return {"status": "sent", "utf8_bytes": len(text.encode("utf-8")),
                "executed": None}

    def next_event(self, timeout: float | None = None) -> dict:
        """Idle streams have no deadline unless the caller supplies one.

        ResyncRequired means raw output was lost: use the following Grid baseline,
        not concatenated raw output as a complete transcript. Events stay ordered.
        """
        event = self._connection.read(timeout)
        body = event.get("frame") if event.get("ev") == "damage" else event
        if not isinstance(body, dict) or body.get("id") != self.session.id:
            raise HydraError("stream event belongs to another session")
        if (type(event.get("live_output_generation")) is not int
                or event["live_output_generation"] != 1):
            raise HydraError("stream event has no matching attachment identity")
        payload = event.get("grid", body)
        if isinstance(payload, dict) and "generation" in payload:
            if payload["generation"] != self.session.generation:
                raise HydraError("stream session lifetime changed")
        return event

    @staticmethod
    def output_bytes(event: dict) -> bytes:
        if event.get("ev") != "output":
            return b""
        try:
            return base64.b64decode(event["data"], validate=True)
        except (KeyError, ValueError, TypeError) as error:
            raise HydraError("invalid raw-output encoding") from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, help="explicit Hydra Unix socket path")
    parser.add_argument("--timeout", type=float, default=5.0, help="connection/query seconds")
    parser.add_argument("operation", choices=("info", "list", "watch", "send"))
    parser.add_argument("--session", help="exact session id for watch/send")
    parser.add_argument("--generation", help="optional expected generation from list")
    args = parser.parse_args()
    client = Hydra(args.socket, args.timeout)
    if args.operation == "info":
        print(json.dumps(client.info()))
    elif args.operation == "list":
        print(json.dumps([vars(session) for session in client.sessions()]))
    else:
        matches = [s for s in client.sessions() if s.id == args.session]
        if len(matches) != 1:
            raise HydraError("choose one live session id returned by list")
        session = matches[0]
        if args.generation and args.generation != session.generation:
            raise HydraError("session generation changed; no input sent")
        with client.attach(session, raw_output=args.operation == "watch") as stream:
            if args.operation == "send":
                data = sys.stdin.buffer.read(MAX_LINE_BYTES + 1)
                if len(data) > MAX_LINE_BYTES:
                    raise HydraError("input exceeds Hydra's wire limit; nothing sent")
                print(json.dumps(stream.send_text(data.decode("utf-8"))))
            else:
                print(json.dumps(stream.initial), flush=True)
                while True:
                    print(json.dumps(stream.next_event()), flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except (HydraError, OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        sys.exit(1)
