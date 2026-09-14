"""Run a real retained-session round trip using only a disposable local Hydra daemon."""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from hydra_client import Hydra, HydraError, SessionStream, _Connection

PROGRAM = r"""
import json, signal, sys
signal.alarm(45)
print('SUM_READY', flush=True)
for line in sys.stdin:
    value = json.loads(line)
    if value.get('quit'):
        break
    print('SUM_RESULT=' + str(value['a'] + value['b']), flush=True)
"""


def observed(stream: SessionStream, marker: bytes, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    tail = b""
    while marker not in tail:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("owned demo output was not observed")
        event = stream.next_event(remaining)
        if event["ev"] == "resync_required":
            raise HydraError("demo output stream lost bytes; cannot assert a complete round trip")
        tail = (tail + stream.output_bytes(event))[-4096:]


def run(app: Path, daemon_binary: Path) -> dict:
    app, daemon_binary = app.resolve(strict=True), daemon_binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="hydra-sdk-", dir="/tmp") as folder:
        endpoint = str(Path(folder) / "owned.sock")
        base = str(Path(folder) / "records")
        session_id = "sdk-demo-" + uuid.uuid4().hex
        daemon = subprocess.Popen([str(daemon_binary), endpoint],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        streams = []
        try:
            client = Hydra(endpoint)
            deadline = time.monotonic() + 5
            while True:
                try:
                    info = client.info()
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if daemon.poll() is not None or time.monotonic() >= deadline:
                        raise HydraError("owned demo daemon did not become ready")
                    time.sleep(0.02)
            assert client.sessions() == [], "fresh owned daemon should have no sessions"
            launch = subprocess.run(
                [str(app), "launch", "--base", base, "--socket", endpoint,
                 "--daemon", str(daemon_binary), "--session-id", session_id,
                 "--cwd", folder, "--record-window", "--window-id", "sdk-demo-window",
                 "--tab-id", "sdk-demo-tab", "--tab-title", "Developer sum demo",
                 "--no-run-renderer", "--keep-daemon", "--", sys.executable, "-u", "-c", PROGRAM],
                capture_output=True, timeout=20, check=True)
            launch_result = json.loads(launch.stdout)
            session = next(s for s in client.sessions() if s.id == session_id)
            first = client.attach(session, raw_output=True)
            second = client.attach(session, raw_output=True)
            streams.extend([first, second])
            sent = first.send_text('{"a":19,"b":23}\n')
            observed(first, b"SUM_RESULT=42")
            observed(second, b"SUM_RESULT=42")
            # An old exact lifetime cannot read a replacement's terminal content.
            try:
                with client.attach(replace(session, generation=str(uuid.uuid4()))):
                    raise AssertionError("wrong-generation attach unexpectedly succeeded")
            except HydraError as error:
                if not str(error).startswith("attach refused:"):
                    raise
            # Exercise the real wire's Write refusal, without weakening the public helper.
            wrong_writer = _Connection(endpoint, 5)
            try:
                wrong_writer.send({"op": "write", "id": session_id,
                                   "expected_generation": str(uuid.uuid4()), "data": "BAD_INPUT\n"})
                try:
                    wrong_writer.read(5)
                    raise AssertionError("wrong-generation write was not refused")
                except HydraError as error:
                    if "daemon disconnected" not in str(error):
                        raise
            finally:
                wrong_writer.close()
            first.close()
            second.close()
            assert session in client.sessions(), "disconnect ended the retained session"
            with client.attach(session, raw_output=True) as revisited:
                revisited.send_text('{"a":20,"b":23}\n')
                observed(revisited, b"SUM_RESULT=43")
                revisited.send_text('{"quit":true}\n')
            view = subprocess.run(
                [str(app), "window", "show", "--base", base, "--window-id", "sdk-demo-window"],
                capture_output=True, timeout=10, check=True)
            layout = json.loads(view.stdout)
            assert launch_result["ok"] is True and layout["ok"] is True
            assert layout["window_id"] == "sdk-demo-window"
            assert any(tab["session_id"] == session_id and tab["tab_id"] == "sdk-demo-tab"
                       for tab in layout["tabs"]), "CLI did not retain its window/tab record"
            return {"protocol_version": info["protocol_version"],
                    "daemon_build_version": info["build_version"],
                    "daemon_sha256": hashlib.sha256(daemon_binary.read_bytes()).hexdigest(),
                    "app_sha256": hashlib.sha256(app.read_bytes()).hexdigest(),
                    "launch_reported_ok": launch_result.get("ok"),
                    "window_record_reported_ok": layout.get("ok"),
                    "initial_empty_session_list": True,
                    "two_clients_observed_sum": True, "disconnect_preserved_session": True,
                    "revisited_same_generation": True, "stale_attach_refused": True,
                    "stale_input_refused": True, "send_status": sent["status"],
                    "execution_receipt_available": False, "gui_opened": False,
                    "fixture_results": [42, 43]}
        finally:
            for stream in streams:
                stream.close()
            # Only the exact owned Popen child; never a process-name lookup or user daemon.
            if daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--daemon", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(run(arguments.app, arguments.daemon), sort_keys=True))
