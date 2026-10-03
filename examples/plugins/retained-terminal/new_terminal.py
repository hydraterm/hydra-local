"""A real Hydra plugin: create a durable terminal through the app's existing CLI."""
import argparse
import os
import subprocess
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--headless", action="store_true", help="qualification without a GUI")
parser.add_argument("--command", nargs=argparse.REMAINDER, help="optional terminal argv")
args = parser.parse_args()
identity = "plugin-" + uuid.uuid4().hex
command = [os.environ["HYDRA_BIN_PATH"], "launch", "--base", os.environ["HYDRA_BASE_DIR"],
           "--session-id", identity, "--record-window", "--window-id", identity,
           "--tab-id", identity, "--tab-title", "Plugin terminal", "--keep-daemon"]
if os.environ.get("HYDRA_SOCKET_PATH"):
    command.extend(["--socket", os.environ["HYDRA_SOCKET_PATH"]])
if args.headless:
    command.append("--no-run-renderer")
if args.command:
    command.extend(["--", *args.command])
raise SystemExit(subprocess.call(command))
