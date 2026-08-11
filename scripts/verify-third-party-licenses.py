#!/usr/bin/env python3
"""Focused deterministic verification for the binary third-party licence generator."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "scripts/generate-third-party-licenses.py"
PROOFS: list[str] = []


def load_generator():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("hydra_third_party_licenses", GENERATOR)
    if spec is None or spec.loader is None:
        raise SystemExit("third-party-license-tests: cannot load generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def check(condition: bool, name: str) -> None:
    if not condition:
        raise AssertionError(name)
    PROOFS.append(name)
    print(f"third-party-license-tests: PASS {name}")


def main() -> int:
    generator = load_generator()
    policy = generator.load_policy()

    collector = generator.MaterialCollector()
    first = collector.add(b"same bytes\n", "one@1", "LICENSE", "license")
    second = collector.add(b"same bytes\n", "two@2", "COPYING", "license")
    check(first == second and len(collector.groups) == 1, "byte-identical material deduplicates")
    check(
        len(collector.groups[first].attributions) == 2,
        "deduplication retains every package attribution",
    )

    generated: dict[str, bytes] = {}
    audits = []
    cargo_lock = generator.parse_cargo_lock()
    for target in sorted(policy["targets"]):
        document, audit = generator.generate(target)
        repeated, repeated_audit = generator.generate(target)
        check(document == repeated, f"{target} generation is byte-stable")
        check(
            audit.cargo_components == repeated_audit.cargo_components
            and audit.npm_components == repeated_audit.npm_components
            and audit.protocol_sources == repeated_audit.protocol_sources,
            f"{target} graph result is stable",
        )
        check(
            len(audit.cargo_components) == policy["targets"][target]["cargo_packages"],
            f"{target} Cargo proof count is exact and nonzero",
        )
        metadata = generator.cargo_metadata(target)
        cargo_packages = generator.selected_cargo_packages(metadata)
        closure_digest = generator.canonical_json_sha256(
            generator.cargo_closure_records(metadata, cargo_packages, cargo_lock)
        )
        check(
            closure_digest == policy["targets"][target]["cargo_closure_sha256"],
            f"{target} Cargo identities, licences, sources, features, and archives are exact",
        )
        check(
            audit.npm_components == set(policy["npm_runtime"]),
            f"{target} npm runtime proof set is the reviewed five",
        )
        check(str(ROOT).encode() not in document, f"{target} omits the public source path")
        check(str(pathlib.Path.home()).encode() not in document, f"{target} omits the builder home")
        generated[target] = document
        audits.append(audit)

    npm_lock = json.loads((ROOT / "dashboard-ui/package-lock.json").read_text())
    npm_paths = generator.npm_runtime_paths(npm_lock)
    npm_closure_digest = generator.canonical_json_sha256(
        generator.npm_runtime_closure_records(npm_lock, npm_paths)
    )
    check(
        npm_closure_digest == policy["npm_runtime_closure_sha256"],
        "npm runtime identities, dependency edges, tarball URLs, and integrity values are exact",
    )
    bundle_proof = subprocess.run(
        ["node", str(ROOT / "scripts/verify-dashboard-bundle-closure.mjs")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if bundle_proof.returncode != 0:
        raise AssertionError(
            "dashboard bundle closure proof failed: "
            + " ".join((bundle_proof.stdout + bundle_proof.stderr).split())
        )
    check(
        bundle_proof.stdout.startswith("dashboard-bundle-closure: PASS packages=3 modules="),
        "Vite output contains exactly the three reviewed shipped npm packages",
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as handle:
        changed_bundle_policy = json.loads(
            (ROOT / "scripts/third-party-license-policy.json").read_text()
        )
        changed_bundle_policy["npm_bundle_packages"].remove("scheduler@0.23.2")
        json.dump(changed_bundle_policy, handle)
        handle.flush()
        rejected_bundle = subprocess.run(
            [
                "node",
                str(ROOT / "scripts/verify-dashboard-bundle-closure.mjs"),
                "--policy",
                handle.name,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
    check(
        rejected_bundle.returncode != 0 and 'extra=["scheduler@0.23.2"]' in rejected_bundle.stderr,
        "an npm package entering the Vite bundle without approval fails closed",
    )

    original_install_lock = generator.NPM_INSTALL_LOCK
    try:
        with tempfile.TemporaryDirectory() as temporary:
            generator.NPM_INSTALL_LOCK = pathlib.Path(temporary) / "missing-package-lock.json"
            try:
                generator.generate("aarch64-apple-darwin")
            except generator.GenerationError:
                PROOFS.append("missing npm ci installation receipt fails closed")
                print("third-party-license-tests: PASS missing npm ci installation receipt fails closed")
            else:
                raise AssertionError("missing npm ci installation receipt did not fail closed")
    finally:
        generator.NPM_INSTALL_LOCK = original_install_lock

    rootless = set().union(*(audit.rootless_components for audit in audits))
    check(
        rootless == set(policy["rootless_cargo_fallbacks"]),
        "every rootless fallback is exact, current, and exercised",
    )
    included = set().union(*(audit.nested_includes for audit in audits))
    expected_included = {
        (rule["package"], rule["path"]) for rule in policy["nested_material"]["include"]
    }
    check(included == expected_included, "every reviewed nested include is exercised")
    excluded = set().union(*(audit.nested_excludes for audit in audits))
    expected_excluded = {
        (rule["package"], rule["path"]) for rule in policy["nested_material"]["exclude"]
    }
    check(excluded == expected_excluded, "every reviewed nested exclusion is exercised")
    protocol_sources = set().union(*(audit.protocol_sources for audit in audits))
    expected_protocol_sources = {
        (rule["package"], path)
        for rule in policy["generated_protocol_sources"]
        for path in rule["paths"]
    }
    check(
        protocol_sources == expected_protocol_sources,
        "every reviewed generated Wayland protocol source is exercised",
    )
    check(
        len(protocol_sources) == 0,
        "the reviewed target graphs consume no generated Wayland XML sources",
    )
    mpl = set().union(*(audit.mpl_components for audit in audits))
    check(mpl == set(policy["mpl_source_packages"]), "MPL source references cover the exact graph")

    mac = generated["aarch64-apple-darwin"]
    linux = generated["x86_64-unknown-linux-gnu"]
    check(b"wayland.xml" not in mac, "macOS artifact excludes generated Wayland provenance")
    check(
        b"wayland-client@" not in linux and b"wayland-protocols@" not in linux,
        "Linux artifact excludes generated core and official Wayland bindings",
    )
    check(
        all(
            not any(
                component.startswith(prefix)
                for prefix in (
                    "wayland-protocols-plasma@",
                    "wayland-protocols-wlr@",
                    "smithay-client-toolkit@",
                    "wayland-client@",
                    "wayland-protocols@",
                )
            )
            for audit in audits
            if audit.family == "linux"
            for component in audit.cargo_components
        ),
        "both Linux target graphs exclude all generated Wayland, Plasma, WLR and Smithay clients",
    )
    check(
        b"gdkwayland-sys@0.18.2" in linux and b"wayland-sys@0.31.11" in linux,
        "Linux artifact retains the GTK and Wayland system-library FFI notices",
    )
    check(
        b"wayland.xml" not in linux,
        "Linux artifact contains no generated Wayland XML provenance",
    )
    check(
        b"plasma-wayland-protocols/" not in linux and b"wlr-protocols/" not in linux,
        "Linux artifact contains no removed Plasma or WLR protocol provenance",
    )
    check(
        b"Copyright \xc2\xa9 2015 David Cuddeback" in linux
        and b"serial@0.4.0  notice  README.md" in linux,
        "serial 0.4.0 copyright notice is preserved",
    )
    check(
        b"https://crates.io/api/v1/crates/option-ext/0.2.0/download" in linux,
        "MPL source reference is version-specific",
    )

    try:
        generator.generate("unreviewed-target")
    except generator.GenerationError:
        PROOFS.append("unreviewed target fails closed")
        print("third-party-license-tests: PASS unreviewed target fails closed")
    else:
        raise AssertionError("unreviewed target did not fail closed")

    def policy_failure(mutator, target: str, name: str) -> None:
        changed = json.loads((ROOT / "scripts/third-party-license-policy.json").read_text())
        mutator(changed)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as handle:
            json.dump(changed, handle)
            handle.flush()
            try:
                generator.generate(target, pathlib.Path(handle.name))
            except generator.GenerationError:
                PROOFS.append(name)
                print(f"third-party-license-tests: PASS {name}")
            else:
                raise AssertionError(f"{name}: changed policy unexpectedly passed")

    policy_failure(
        lambda changed: changed.__setitem__("cargo_lock_sha256", "0" * 64),
        "aarch64-apple-darwin",
        "unreviewed Cargo lock digest fails closed",
    )
    policy_failure(
        lambda changed: changed["targets"]["aarch64-apple-darwin"].__setitem__(
            "cargo_closure_sha256", "0" * 64
        ),
        "aarch64-apple-darwin",
        "unreviewed per-target Cargo closure digest fails closed",
    )
    policy_failure(
        lambda changed: changed.__setitem__("npm_runtime_closure_sha256", "0" * 64),
        "aarch64-apple-darwin",
        "unreviewed npm runtime closure digest fails closed",
    )
    policy_failure(
        lambda changed: changed["npm_runtime"]["react@18.3.1"]["materials"].__setitem__(
            "LICENSE", "0" * 64
        ),
        "aarch64-apple-darwin",
        "unreviewed installed npm licence bytes fail closed",
    )
    policy_failure(
        lambda changed: changed["rootless_cargo_fallbacks"].pop("block@0.1.6"),
        "aarch64-apple-darwin",
        "missing rootless fallback fails closed",
    )
    policy_failure(
        lambda changed: changed["nested_material"]["include"].__setitem__(
            slice(None),
            [
                rule
                for rule in changed["nested_material"]["include"]
                if rule["package"] != "regex-syntax@0.8.10"
            ],
        ),
        "aarch64-apple-darwin",
        "missing nested licence decision fails closed",
    )
    policy_failure(
        lambda changed: changed["generated_protocol_sources"].append(
            {
                "package": "wayland-client@0.31.14",
                "targets": ["linux"],
                "paths": ["wayland.xml"],
            }
        ),
        "x86_64-unknown-linux-gnu",
        "unreviewed generated Wayland protocol source rule fails closed",
    )

    check(len(PROOFS) == 56, "focused suite count assertion observed all 56 substantive proofs")
    print(
        "third-party-license-tests: RESULT pass "
        f"proofs={len(PROOFS)} targets={len(policy['targets'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
