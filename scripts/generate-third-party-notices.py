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


NPM_LOCKS = (
    "dashboard-ui/package-lock.json",
    "web-client/package-lock.json",
    "hydra-cloud/package-lock.json",
)


def npm_dependencies(lock_path: str) -> list[tuple[str, str, str, str]]:
    if lock_path not in NPM_LOCKS:
        raise SystemExit("dependency-notices: unreviewed npm lock path")
    lock = json.loads((ROOT / lock_path).read_text(encoding="utf-8"))
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not packages or "" not in packages:
        raise SystemExit(f"dependency-notices: invalid npm package inventory: {lock_path}")
    rows: set[tuple[str, str, str, str]] = set()
    for path, package in packages.items():
        if not path or "node_modules/" not in path:
            continue
        name = path.rsplit("node_modules/", 1)[1]
        version = package.get("version")
        license_expression = package.get("license")
        if (
            not isinstance(version, str)
            or not version.strip()
            or not isinstance(license_expression, str)
            or not license_expression.strip()
        ):
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
    npm = npm_dependencies(NPM_LOCKS[0])
    browser = npm_dependencies(NPM_LOCKS[1])
    broker = npm_dependencies(NPM_LOCKS[2])
    lines = [
        "# Third-party notices",
        "",
        "Hydra's first-party public source is MIT licensed. It uses third-party software under the terms",
        "listed below. This inventory covers the locked Rust and dashboard graphs plus the separate",
        "Remote library development-tool locks; it does not change or replace any upstream licence.",
        "",
        f"- `Cargo.lock` SHA-256: `{sha256(ROOT / 'Cargo.lock')}`",
        "- `dashboard-ui/package-lock.json` SHA-256: "
        f"`{sha256(ROOT / 'dashboard-ui/package-lock.json')}`",
        f"- Rust dependency versions: {len(rust)}",
        f"- npm dependency versions: {len(npm)}",
        f"- `web-client/package-lock.json` SHA-256: `{sha256(ROOT / NPM_LOCKS[1])}`",
        f"- Browser-core development dependency versions: {len(browser)}",
        f"- `hydra-cloud/package-lock.json` SHA-256: `{sha256(ROOT / NPM_LOCKS[2])}`",
        f"- Broker-core development dependency versions: {len(broker)}",
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
        "## Remote library development tools",
        "",
        "The following locks are build/test tools for the separately consumable Remote libraries,",
        "not additions to the desktop binary dependency policy. The reviewed library artifacts contain",
        "only Hydra code, declarations and their MIT licence; their runtime module graphs contain no",
        "third-party package code. Recheck that boundary after source or build changes.",
        "",
        "These tables include locked optional platform tools, not a claim that every platform archive",
        "was installed or its complete licence material reviewed. Declared metadata can be less detailed",
        "than bundled tool notices. Tool redistributors must review the actual material they ship.",
        "",
        "### Locked browser-core development dependencies",
        "",
        *table(browser),
        "",
        "### Locked broker-core development dependencies",
        "",
        *table(broker),
        "",
        "## Updating this file",
        "",
        "Run `python3 scripts/generate-third-party-notices.py` after any of the four lockfiles changes, then",
        "review every changed licence expression and upstream source before accepting the result.",
        "The generator failing on missing licence metadata is intentional.",
        "",
    ]
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(
        f"dependency-notices: wrote {OUTPUT} with {len(rust)} Rust, {len(npm)} dashboard, "
        f"{len(browser)} browser-tool and {len(broker)} broker-tool rows"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
