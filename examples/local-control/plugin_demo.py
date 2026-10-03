"""Qualify the real app plugin CLI against an owned disposable daemon, without a GUI."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from hydra_client import Hydra
from demo import observed


def run(app: Path, daemon: Path, plugin: Path) -> dict:
    app, daemon, plugin = (path.resolve(strict=True) for path in (app, daemon, plugin))
    with tempfile.TemporaryDirectory(prefix="hydra-plugin-", dir="/tmp") as folder:
        base, endpoint = str(Path(folder) / "base"), str(Path(folder) / "owned.sock")
        owner = subprocess.Popen([str(daemon), endpoint], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def cli(*args, check=True):
            return subprocess.run([str(app), "plugin", *args, "--base", base],
                                  capture_output=True, check=check, timeout=20)
        try:
            client = Hydra(endpoint)
            deadline = time.monotonic() + 5
            while True:
                try:
                    client.info()
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if owner.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("owned daemon did not start")
                    time.sleep(0.02)
            installed = json.loads(cli("install-local", str(plugin)).stdout)
            assert installed["result"]["manifest"]["id"] == "example.retained-terminal"
            assert len(json.loads(cli("list").stdout)["result"]["plugins"]) == 1
            program = "import sys; print('PLUGIN_READY', flush=True);\nfor line in sys.stdin: print('PLUGIN_REPLY=' + line.strip(), flush=True)"
            launched = subprocess.run(
                [str(app), "plugin", "run", "example.retained-terminal", "open", "--base", base,
                 "--socket", endpoint, "--", "--headless", "--command", sys.executable, "-u", "-c", program],
                capture_output=True, check=True, timeout=30)
            assert json.loads(launched.stdout)["ok"] is True
            sessions = client.sessions()
            assert len(sessions) == 1
            with client.attach(sessions[0], raw_output=True) as stream:
                stream.send_text("hello-plugin\n")
                observed(stream, b"PLUGIN_REPLY=hello-plugin")
            assert sessions == client.sessions(), "plugin disconnect must preserve the terminal"
            cli("disable", "example.retained-terminal")
            refused = cli("run", "example.retained-terminal", "open", check=False)
            assert refused.returncode == 1 and b"disabled" in refused.stderr
            cli("enable", "example.retained-terminal")
            cli("remove", "example.retained-terminal")
            assert json.loads(cli("list").stdout)["result"]["plugins"] == []
            assert sessions == client.sessions(), "unregister must preserve the terminal"
            return {"plugin_created_retained_terminal": True, "terminal_round_trip": True,
                    "disable_refused_run": True, "remove_preserved_terminal": True, "gui_opened": False}
        finally:
            if owner.poll() is None:
                owner.terminate()
                try:
                    owner.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    owner.kill()
                    owner.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.app, args.daemon, args.plugin), sort_keys=True))
