#!/usr/bin/env python3
"""Generate the locked third-party dependency inventory for the public source tree."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.parse


ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "THIRD_PARTY_NOTICES.md"


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def markdown(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def rust_dependencies() -> list[tuple[str, str, str, str]]:
    raw = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=ROOT,
        text=True,
    )
    metadata = json.loads(raw)
    workspace = set(metadata["workspace_members"])
    rows: set[tuple[str, str, str, str]] = set()
    for package in metadata["packages"]:
        if package["id"] in workspace:
            continue
        license_expression = package.get("license")
        if not license_expression:
            raise SystemExit(
                f"dependency-notices: Rust package has no declared license: {package['name']} "
                f"{package['version']}"
            )
        source = package.get("repository") or (
            "https://crates.io/crates/"
            f"{urllib.parse.quote(package['name'], safe='')}/{package['version']}"
        )
        rows.add((package["name"], package["version"], license_expression, source))
    return sorted(rows, key=lambda row: (row[0].lower(), row[1], row[2], row[3]))


def npm_dependencies() -> list[tuple[str, str, str, str]]:
    lock = json.loads((ROOT / "dashboard-ui/package-lock.json").read_text(encoding="utf-8"))
    rows: set[tuple[str, str, str, str]] = set()
    for path, package in lock.get("packages", {}).items():
        if not path or "node_modules/" not in path:
            continue
        name = path.rsplit("node_modules/", 1)[1]
        version = package.get("version")
        license_expression = package.get("license")
        if not version or not license_expression:
            raise SystemExit(
                f"dependency-notices: npm package lacks version/license metadata: {path}"
            )
        source = "https://www.npmjs.com/package/" + urllib.parse.quote(name, safe="@/")
        rows.add((name, version, license_expression, source))
    return sorted(rows, key=lambda row: (row[0].lower(), row[1], row[2], row[3]))


def table(rows: list[tuple[str, str, str, str]]) -> list[str]:
    result = ["| Package | Version | Declared licence | Upstream |", "|---|---:|---|---|"]
    for name, version, license_expression, source in rows:
        result.append(
            f"| `{markdown(name)}` | `{markdown(version)}` | `{markdown(license_expression)}` "
            f"| [source]({source}) |"
        )
    return result


def main() -> int:
    rust = rust_dependencies()
    npm = npm_dependencies()
    lines = [
        "# Third-party notices",
        "",
        "Hydra Local is Apache-2.0 licensed. It depends on third-party software under the terms",
        "listed below. This inventory is generated from the exact locked Rust and dashboard",
        "dependency graphs; it does not change or replace any upstream licence.",
        "",
        f"- `Cargo.lock` SHA-256: `{sha256(ROOT / 'Cargo.lock')}`",
        "- `dashboard-ui/package-lock.json` SHA-256: "
        f"`{sha256(ROOT / 'dashboard-ui/package-lock.json')}`",
        f"- Rust dependency versions: {len(rust)}",
        f"- npm dependency versions: {len(npm)}",
        "",
        "The source repository does not vendor these dependencies. Package managers retrieve each",
        "dependency from its named upstream, where the complete corresponding licence and copyright",
        "notices remain available. Binary distributors must carry forward every notice and source",
        "obligation that applies to the exact dependency set they ship.",
        "",
        "## Licence choices and notable obligations",
        "",
        "- Where an upstream declares alternatives with `OR`, Hydra Local elects a permissive",
        "  Apache-2.0, MIT, BSD, ISC, Zlib, BSL-1.0, CC0-1.0, MIT-0 or Unlicense option where",
        "  one is offered; it does not elect a GPL or LGPL alternative.",
        "- The Rust graph includes MPL-2.0 components (`cssparser`, `cssparser-macros`,",
        "  `dtoa-short`, `option-ext` and `selectors`). They are fetched as unmodified upstream",
        "  dependencies. MPL-covered source remains available from the links below.",
        "- The dashboard build graph includes `caniuse-lite`, created by Ben Briggs and maintained",
        "  by the Browserslist project, under CC-BY-4.0. It is build-time compatibility data and is",
        "  not provider artwork or Hydra demo media.",
        "- Linux uses Tao/GTK as its owner loop and builds the residual winit dependency X11-only.",
        "  Its reviewed normal/build closure consumes no Wayland XML code-generation inputs and",
        "  excludes wayland-client, wayland-protocols, Plasma, WLR and Smithay client-toolkit.",
        "- The `serial 0.4.0` archive has no root licence file. Binary notices preserve its README",
        "  copyright for David Cuddeback and pair it with the exact reviewed MIT fallback text.",
        "- No third-party coding-agent logos, provider icons, screenshots, recordings or demo media",
        "  are included in this prepared public tree.",
        "",
        "## Locked Rust dependencies",
        "",
        *table(rust),
        "",
        "## Locked dashboard dependencies",
        "",
        *table(npm),
        "",
        "## Updating this file",
        "",
        "Run `python3 scripts/generate-third-party-notices.py` after either lockfile changes, then",
        "review every changed licence expression and upstream source before accepting the result.",
        "The generator failing on missing licence metadata is intentional.",
        "",
    ]
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(
        f"dependency-notices: wrote {OUTPUT} with {len(rust)} Rust and {len(npm)} npm rows"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
