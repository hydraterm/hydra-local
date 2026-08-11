#!/usr/bin/env python3
"""Build the target-specific third-party licence artifact for Hydra Local binaries.

This generator is intentionally fail closed. It proves exact per-target Cargo and npm runtime
closures, verifies each Cargo archive against its lockfile checksum, includes every applicable root
licence/copyright/NOTICE file and generated Wayland XML input verbatim, and requires an explicit
reviewed policy decision for rootless crates and nested licence-like files. The result is a
packaging artifact; it is not a checked-in generated source file.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
from typing import Any, Iterable


ROOT = pathlib.Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT / "scripts/third-party-license-policy.json"
CARGO_LOCK = ROOT / "Cargo.lock"
NPM_LOCK = ROOT / "dashboard-ui/package-lock.json"
NPM_MODULES = ROOT / "dashboard-ui/node_modules"
NPM_INSTALL_LOCK = NPM_MODULES / ".package-lock.json"
NPM_BUNDLE_VERIFIER = ROOT / "scripts/verify-dashboard-bundle-closure.mjs"

ROOT_MATERIAL_PREFIXES = (
    "LICENSE",
    "LICENCE",
    "COPYING",
    "COPYRIGHT",
    "NOTICE",
    "NOTICES",
    "AUTHORS",
    "PATENTS",
    "THIRD-PARTY",
    "THIRD_PARTY",
    "THIRDPARTY",
)
SOURCE_FILE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".mm", ".rs"}
WAYLAND_PROTOCOL_REFERENCE = re.compile(
    rb'(?:wayland_protocol!|generate_(?:interfaces|client_code|server_code)!)'
    rb'\s*\(\s*"([^"\n]+\.xml)"',
    re.DOTALL,
)


class GenerationError(RuntimeError):
    """A fail-closed policy or input violation."""


def fail(message: str) -> None:
    raise GenerationError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256_bytes(encoded)


def clean_field(value: Any) -> str:
    return " ".join(str(value).split())


def package_key(name: str, version: str) -> str:
    return f"{name}@{version}"


def validate_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        fail(f"{context} keys changed (missing={missing}, extra={extra})")


def load_policy(path: pathlib.Path = POLICY_PATH) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read reviewed policy {path}: {error}")
    if not isinstance(policy, dict):
        fail("reviewed policy must be a JSON object")
    validate_exact_keys(
        policy,
        {
            "schema",
            "cargo_lock_sha256",
            "npm_lock_sha256",
            "targets",
            "npm_runtime",
            "npm_runtime_closure_sha256",
            "npm_bundle_packages",
            "fallback_texts",
            "rootless_cargo_fallbacks",
            "nested_material",
            "generated_protocol_sources",
            "mpl_source_packages",
        },
        "reviewed policy",
    )
    if policy["schema"] != "hydra.third-party-license-policy.v2":
        fail(f"unsupported reviewed policy schema: {policy['schema']!r}")
    if sha256_file(CARGO_LOCK) != policy["cargo_lock_sha256"]:
        fail("Cargo.lock changed without a third-party licence policy review")
    if sha256_file(NPM_LOCK) != policy["npm_lock_sha256"]:
        fail("dashboard-ui/package-lock.json changed without a third-party licence policy review")
    if not isinstance(policy["targets"], dict) or not policy["targets"]:
        fail("reviewed policy has no allowed targets")
    for target, target_policy in policy["targets"].items():
        if not isinstance(target_policy, dict):
            fail(f"target policy is not an object: {target}")
        validate_exact_keys(
            target_policy,
            {"family", "cargo_packages", "cargo_closure_sha256"},
            f"target {target}",
        )
        if target_policy["family"] not in {"macos", "linux"}:
            fail(f"target has unreviewed family: {target}")
        if not isinstance(target_policy["cargo_packages"], int) or target_policy["cargo_packages"] < 1:
            fail(f"target has invalid Cargo package count: {target}")
        if not re.fullmatch(r"[0-9a-f]{64}", target_policy["cargo_closure_sha256"]):
            fail(f"target has invalid Cargo closure digest: {target}")
    if not re.fullmatch(r"[0-9a-f]{64}", policy["npm_runtime_closure_sha256"]):
        fail("reviewed policy has an invalid npm runtime closure digest")
    if not isinstance(policy["npm_runtime"], dict) or not policy["npm_runtime"]:
        fail("reviewed policy has no npm runtime closure")
    if (
        not isinstance(policy["npm_bundle_packages"], list)
        or not policy["npm_bundle_packages"]
        or len(policy["npm_bundle_packages"]) != len(set(policy["npm_bundle_packages"]))
        or not all(isinstance(key, str) for key in policy["npm_bundle_packages"])
    ):
        fail("reviewed policy has an invalid npm bundle package set")
    if not set(policy["npm_bundle_packages"]).issubset(policy["npm_runtime"]):
        fail("npm bundle package set is outside the reviewed runtime closure")
    for key, npm_policy in policy["npm_runtime"].items():
        if not isinstance(npm_policy, dict):
            fail(f"npm runtime policy is not an object: {key}")
        validate_exact_keys(
            npm_policy,
            {"license", "resolved", "integrity", "dependencies", "materials"},
            f"npm runtime {key}",
        )
        if not isinstance(npm_policy["dependencies"], dict):
            fail(f"npm runtime dependency map is malformed: {key}")
        if not isinstance(npm_policy["materials"], dict) or not npm_policy["materials"]:
            fail(f"npm runtime material policy is empty: {key}")
        for path, digest in npm_policy["materials"].items():
            if (
                not isinstance(path, str)
                or "/" in path
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                fail(f"npm runtime material policy is invalid: {key} ({path})")
    validate_exact_keys(policy["nested_material"], {"include", "exclude"}, "nested policy")
    for group in ("include", "exclude"):
        if not isinstance(policy["nested_material"][group], list):
            fail(f"nested policy {group} must be a list")
    if not isinstance(policy["generated_protocol_sources"], list):
        fail("generated protocol source policy must be a list")
    for rule in policy["generated_protocol_sources"]:
        if not isinstance(rule, dict):
            fail("generated protocol source rule is not an object")
        validate_exact_keys(
            rule,
            {"package", "targets", "paths"},
            "generated protocol source rule",
        )
        if not isinstance(rule["paths"], list) or not rule["paths"]:
            fail(f"generated protocol source rule has no paths: {rule.get('package')}")
        if len(rule["paths"]) != len(set(rule["paths"])):
            fail(f"generated protocol source rule repeats a path: {rule.get('package')}")
        for source_path in rule["paths"]:
            if not isinstance(source_path, str) or not source_path.endswith(".xml"):
                fail(f"generated protocol source rule has an invalid path: {rule}")
    for text_name, text_policy in policy["fallback_texts"].items():
        if not isinstance(text_policy, dict):
            fail(f"fallback text policy is not an object: {text_name}")
        validate_exact_keys(text_policy, {"path", "sha256"}, f"fallback text {text_name}")
        source = (ROOT / text_policy["path"]).resolve()
        try:
            source.relative_to(ROOT)
        except ValueError:
            fail(f"reviewed fallback text escapes the public tree: {text_name}")
        if not source.is_file() or sha256_file(source) != text_policy["sha256"]:
            fail(f"reviewed fallback text is missing or changed: {text_name}")
    return policy


def parse_cargo_lock() -> dict[tuple[str, str, str], dict[str, str]]:
    """Parse only the scalar package identity fields from Cargo.lock.

    This deliberately small parser keeps the format handling explicit and independently auditable,
    where tomllib is unavailable.  All values we accept are JSON-compatible quoted TOML strings.
    """

    text = CARGO_LOCK.read_text(encoding="utf-8")
    records: dict[tuple[str, str, str], dict[str, str]] = {}
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        fields: dict[str, str] = {}
        for match in re.finditer(
            r'(?m)^(name|version|source|checksum)\s*=\s*("(?:[^"\\]|\\.)*")\s*$',
            block,
        ):
            fields[match.group(1)] = json.loads(match.group(2))
        if "name" not in fields or "version" not in fields:
            fail("Cargo.lock contains a package without a scalar name/version")
        source = fields.get("source", "")
        key = (fields["name"], fields["version"], source)
        if key in records:
            fail(f"Cargo.lock contains a duplicate package identity: {key}")
        records[key] = fields
    if not records:
        fail("Cargo.lock package parser found no packages")
    return records


def cargo_metadata(target: str) -> dict[str, Any]:
    try:
        output = subprocess.check_output(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--filter-platform",
                target,
            ],
            cwd=ROOT,
            text=True,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None) or str(error)
        fail(f"cargo metadata failed for {target}: {clean_field(detail)}")
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        fail(f"cargo metadata returned invalid JSON for {target}: {error}")


def selected_cargo_packages(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    package_by_id = {package["id"]: package for package in metadata["packages"]}
    resolve = metadata.get("resolve")
    if not resolve:
        fail("cargo metadata has no resolved graph")
    node_by_id = {node["id"]: node for node in resolve["nodes"]}
    workspace = set(metadata["workspace_members"])
    selected = set(workspace)
    pending = list(workspace)
    while pending:
        node_id = pending.pop()
        node = node_by_id.get(node_id)
        if node is None:
            fail(f"resolved graph has no node for {node_id}")
        for dependency in node["deps"]:
            dependency_kinds = dependency.get("dep_kinds")
            if not isinstance(dependency_kinds, list) or not dependency_kinds:
                fail(f"resolved dependency has no dependency kinds: {dependency}")
            ships = any(item.get("kind") in (None, "build") for item in dependency_kinds)
            dependency_id = dependency["pkg"]
            if ships and dependency_id not in selected:
                selected.add(dependency_id)
                pending.append(dependency_id)
    result = []
    for package_id in selected - workspace:
        package = package_by_id[package_id]
        source = package.get("source")
        if source is None:
            fail(
                "non-workspace path dependency entered the binary graph without a reviewed "
                f"licence rule: {package_key(package['name'], package['version'])}"
            )
        if source != "registry+https://github.com/rust-lang/crates.io-index":
            fail(
                "non-crates.io Cargo source entered the binary graph without a reviewed rule: "
                f"{package_key(package['name'], package['version'])} ({source})"
            )
        if not package.get("license"):
            fail(f"Cargo package has no declared licence: {package_key(package['name'], package['version'])}")
        result.append(package)
    return sorted(result, key=lambda package: (package["name"].lower(), package["version"]))


def cargo_closure_records(
    metadata: dict[str, Any],
    packages: list[dict[str, Any]],
    lock: dict[tuple[str, str, str], dict[str, str]],
) -> list[dict[str, Any]]:
    """Return the exact reviewed identity of the target's shipped Cargo closure.

    The local registry manifest path is deliberately excluded because it contains a builder-specific
    Cargo home.  The registry source plus the archive checksum identifies that manifest and every
    other archive byte without embedding a personal path.
    """

    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        fail("cargo metadata has no resolved nodes for closure proof")
    features_by_id = {node["id"]: sorted(node.get("features", [])) for node in resolve["nodes"]}
    records: list[dict[str, Any]] = []
    for package in packages:
        source = package["source"]
        lock_record = lock.get((package["name"], package["version"], source))
        if lock_record is None:
            fail(
                "resolved Cargo package has no exact lock record while proving closure: "
                f"{package_key(package['name'], package['version'])}"
            )
        checksum = lock_record.get("checksum")
        if not checksum or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            fail(
                "resolved Cargo package has no archive checksum while proving closure: "
                f"{package_key(package['name'], package['version'])}"
            )
        package_id = package["id"]
        if package_id not in features_by_id:
            fail(f"resolved Cargo package has no feature record: {package_id}")
        records.append(
            {
                "name": package["name"],
                "version": package["version"],
                "license": package["license"],
                "source": source,
                "archive_sha256": checksum,
                "features": features_by_id[package_id],
            }
        )
    return sorted(
        records,
        key=lambda item: (item["name"].lower(), item["version"], item["source"]),
    )


def cargo_archive_path(package: dict[str, Any]) -> pathlib.Path:
    package_dir = pathlib.Path(package["manifest_path"]).parent
    registry_source = package_dir.parent
    if registry_source.parent.name != "src" or registry_source.parent.parent.name != "registry":
        fail(f"unexpected Cargo registry source path for {package_key(package['name'], package['version'])}")
    return (
        registry_source.parent.parent
        / "cache"
        / registry_source.name
        / f"{package['name']}-{package['version']}.crate"
    )


def cargo_archive_files(
    package: dict[str, Any], lock_record: dict[str, str]
) -> dict[str, bytes]:
    key = package_key(package["name"], package["version"])
    checksum = lock_record.get("checksum")
    if not checksum or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        fail(f"Cargo package has no reviewed SHA-256 checksum: {key}")
    archive = cargo_archive_path(package)
    if not archive.is_file():
        fail(f"locked Cargo archive is absent for {key}; run cargo fetch --locked first")
    if sha256_file(archive) != checksum:
        fail(f"locked Cargo archive checksum mismatch: {key}")
    expected_prefix = f"{package['name']}-{package['version']}/"
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            for member in bundle.getmembers():
                if not member.isfile():
                    continue
                if not member.name.startswith(expected_prefix):
                    fail(f"Cargo archive has an unexpected root: {key} ({member.name})")
                relative = member.name[len(expected_prefix) :]
                pure = pathlib.PurePosixPath(relative)
                if not relative or pure.is_absolute() or ".." in pure.parts:
                    fail(f"Cargo archive has an unsafe member path: {key} ({member.name})")
                stream = bundle.extractfile(member)
                if stream is None:
                    fail(f"Cargo archive member cannot be read: {key} ({relative})")
                if relative in files:
                    fail(f"Cargo archive repeats a member: {key} ({relative})")
                files[relative] = stream.read()
    except (OSError, tarfile.TarError) as error:
        fail(f"cannot read locked Cargo archive for {key}: {error}")
    return files


def root_material(path: str) -> bool:
    if "/" in path:
        return False
    upper = path.upper()
    return upper.startswith(ROOT_MATERIAL_PREFIXES)


def suspicious_nested_material(path: str) -> bool:
    if "/" not in path:
        return False
    name = pathlib.PurePosixPath(path).name
    suffix = pathlib.PurePosixPath(name).suffix.lower()
    if suffix in SOURCE_FILE_SUFFIXES:
        return False
    lower = name.lower()
    normalized = lower.replace("-", "").replace("_", "").replace(".", "")
    return (
        "license" in lower
        or "licence" in lower
        or normalized.startswith(
            ("copying", "copyright", "notice", "attribution", "thirdparty", "authors", "patents")
        )
    )


def rule_applies(rule: dict[str, Any], target: str, family: str) -> bool:
    targets = rule.get("targets")
    if not isinstance(targets, list) or not targets or not all(isinstance(item, str) for item in targets):
        fail(f"nested material rule has invalid targets: {rule}")
    return "all" in targets or family in targets or target in targets


def indexed_nested_rules(
    policy: dict[str, Any], group: str, target: str, family: str
) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    required = {"package", "path", "targets", "kind"} if group == "include" else {
        "package",
        "path",
        "targets",
        "reason",
    }
    for rule in policy["nested_material"][group]:
        if not isinstance(rule, dict):
            fail(f"nested material {group} rule is not an object")
        validate_exact_keys(rule, required, f"nested material {group} rule")
        if not rule_applies(rule, target, family):
            continue
        key = (rule["package"], rule["path"])
        if key in result:
            fail(f"duplicate active nested material {group} rule: {key}")
        if group == "include" and rule["kind"] not in {"license", "notice", "provenance"}:
            fail(f"nested include has an unreviewed kind: {rule}")
        if group == "exclude" and not clean_field(rule["reason"]):
            fail(f"nested exclusion has no review reason: {rule}")
        result[key] = rule
    return result


def indexed_protocol_rules(
    policy: dict[str, Any], target: str, family: str
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for rule in policy["generated_protocol_sources"]:
        if not rule_applies(rule, target, family):
            continue
        package = rule["package"]
        if package in result:
            fail(f"duplicate active generated protocol source rule: {package}")
        paths = set(rule["paths"])
        for path in paths:
            pure = pathlib.PurePosixPath(path)
            if pure.is_absolute() or ".." in pure.parts:
                fail(f"generated protocol source rule has an unsafe path: {package} ({path})")
        result[package] = paths
    return result


def referenced_wayland_protocols(files: dict[str, bytes]) -> set[str]:
    references: set[str] = set()
    for path, data in files.items():
        if not path.endswith(".rs"):
            continue
        for match in WAYLAND_PROTOCOL_REFERENCE.finditer(data):
            reference = match.group(1).decode("utf-8")
            if reference.startswith("./"):
                reference = reference[2:]
            pure = pathlib.PurePosixPath(reference)
            if pure.is_absolute() or ".." in pure.parts:
                fail(f"generated Wayland protocol reference is unsafe: {reference}")
            references.add(reference)
    return references


@dataclasses.dataclass(frozen=True)
class MaterialAttribution:
    component: str
    path: str
    kind: str


@dataclasses.dataclass
class MaterialGroup:
    data: bytes
    attributions: list[MaterialAttribution]


@dataclasses.dataclass
class Component:
    ecosystem: str
    name: str
    version: str
    declared_license: str
    source: str
    integrity_label: str
    integrity_value: str
    authors: list[str]
    materials: list[tuple[str, str, str]]


@dataclasses.dataclass
class GenerationAudit:
    target: str
    family: str
    cargo_components: set[str]
    npm_components: set[str]
    rootless_components: set[str]
    nested_includes: set[tuple[str, str]]
    nested_excludes: set[tuple[str, str]]
    protocol_sources: set[tuple[str, str]]
    mpl_components: set[str]
    material_groups: int


class MaterialCollector:
    def __init__(self) -> None:
        self.groups: dict[str, MaterialGroup] = {}

    def add(self, data: bytes, component: str, path: str, kind: str) -> str:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as error:
            fail(f"licence material is not UTF-8 text: {component} ({path}): {error}")
        digest = sha256_bytes(data)
        attribution = MaterialAttribution(component=component, path=path, kind=kind)
        if digest in self.groups:
            if self.groups[digest].data != data:
                fail(f"SHA-256 collision while deduplicating licence material: {digest}")
            if attribution in self.groups[digest].attributions:
                fail(f"duplicate licence attribution: {component} ({path})")
            self.groups[digest].attributions.append(attribution)
        else:
            self.groups[digest] = MaterialGroup(data=data, attributions=[attribution])
        return digest


def material_kind(path: str) -> str:
    upper = pathlib.PurePosixPath(path).name.upper()
    if upper.startswith(("NOTICE", "NOTICES", "ATTRIBUTION", "COPYRIGHT", "AUTHORS")):
        return "notice"
    return "license"


def cargo_components(
    target: str,
    family: str,
    policy: dict[str, Any],
    collector: MaterialCollector,
) -> tuple[list[Component], GenerationAudit]:
    metadata = cargo_metadata(target)
    packages = selected_cargo_packages(metadata)
    expected_count = policy["targets"][target]["cargo_packages"]
    if len(packages) != expected_count:
        fail(
            f"target Cargo graph count changed without review: {target} "
            f"(expected {expected_count}, found {len(packages)})"
        )
    lock = parse_cargo_lock()
    closure_digest = canonical_json_sha256(cargo_closure_records(metadata, packages, lock))
    expected_closure_digest = policy["targets"][target]["cargo_closure_sha256"]
    if closure_digest != expected_closure_digest:
        fail(
            f"target Cargo closure changed without review: {target} "
            f"(expected {expected_closure_digest}, found {closure_digest})"
        )
    includes = indexed_nested_rules(policy, "include", target, family)
    excludes = indexed_nested_rules(policy, "exclude", target, family)
    protocol_rules = indexed_protocol_rules(policy, target, family)
    fallbacks = policy["rootless_cargo_fallbacks"]
    fallback_texts = policy["fallback_texts"]
    components: list[Component] = []
    used_includes: set[tuple[str, str]] = set()
    used_excludes: set[tuple[str, str]] = set()
    used_protocol_sources: set[tuple[str, str]] = set()
    used_fallbacks: set[str] = set()
    mpl_components: set[str] = set()

    for package in packages:
        key = package_key(package["name"], package["version"])
        lock_key = (package["name"], package["version"], package["source"])
        lock_record = lock.get(lock_key)
        if lock_record is None:
            fail(f"resolved Cargo package has no exact lock record: {key}")
        files = cargo_archive_files(package, lock_record)
        selected_files: dict[str, tuple[bytes, str]] = {}
        for path, data in files.items():
            if root_material(path):
                selected_files[path] = (data, material_kind(path))

        license_file = package.get("license_file")
        if license_file:
            relative = pathlib.PurePosixPath(str(license_file)).as_posix()
            if relative.startswith("/") or ".." in pathlib.PurePosixPath(relative).parts:
                fail(f"Cargo package has an unsafe license_file path: {key} ({license_file})")
            if relative not in files:
                fail(f"Cargo package license_file is absent from its archive: {key} ({relative})")
            selected_files[relative] = (files[relative], "license")

        for path in sorted(files):
            if not suspicious_nested_material(path):
                continue
            decision_key = (key, path)
            if decision_key in includes:
                rule = includes[decision_key]
                selected_files[path] = (files[path], rule["kind"])
                used_includes.add(decision_key)
            elif decision_key in excludes:
                used_excludes.add(decision_key)
            else:
                fail(f"nested licence-like Cargo material has no reviewed decision: {key} ({path})")

        for decision_key, rule in includes.items():
            if decision_key[0] != key:
                continue
            path = decision_key[1]
            if path not in files:
                fail(f"reviewed nested Cargo material disappeared: {key} ({path})")
            selected_files[path] = (files[path], rule["kind"])
            used_includes.add(decision_key)
        for decision_key in excludes:
            if decision_key[0] == key and decision_key[1] not in files:
                fail(f"reviewed nested Cargo exclusion disappeared: {key} ({decision_key[1]})")

        expected_protocol_paths = protocol_rules.get(key)
        if expected_protocol_paths is not None:
            found_protocol_paths = referenced_wayland_protocols(files)
            if found_protocol_paths != expected_protocol_paths:
                fail(
                    f"generated Wayland protocol source set changed without review: {key} "
                    f"(missing={sorted(expected_protocol_paths - found_protocol_paths)}, "
                    f"extra={sorted(found_protocol_paths - expected_protocol_paths)})"
                )
            for path in sorted(found_protocol_paths):
                if path not in files:
                    fail(f"generated Wayland protocol source disappeared: {key} ({path})")
                selected_files[path] = (files[path], "provenance")
                used_protocol_sources.add((key, path))

        component_materials: list[tuple[str, str, str]] = []
        has_license_material = any(kind == "license" for _, kind in selected_files.values())
        if not has_license_material:
            fallback = fallbacks.get(key)
            if not isinstance(fallback, dict):
                fail(f"Cargo package has no licence material and no exact reviewed fallback: {key}")
            validate_exact_keys(fallback, {"license", "text"}, f"rootless fallback {key}")
            if fallback["license"] != package["license"]:
                fail(f"Cargo package licence changed from its reviewed fallback: {key}")
            if fallback["text"].lower() not in package["license"].lower():
                fail(f"Cargo fallback text is not one of the package's declared choices: {key}")
            text_policy = fallback_texts.get(fallback["text"])
            if not isinstance(text_policy, dict):
                fail(f"Cargo fallback selects an unknown reviewed text: {key}")
            fallback_path = ROOT / text_policy["path"]
            label = f"reviewed-fallback/{fallback['text']}"
            digest = collector.add(fallback_path.read_bytes(), key, label, "license")
            component_materials.append((digest, label, "license"))
            used_fallbacks.add(key)
        else:
            if key in fallbacks:
                fail(f"obsolete rootless Cargo fallback remains after licence material appeared: {key}")
        for path, (data, kind) in sorted(selected_files.items()):
            digest = collector.add(data, key, path, kind)
            component_materials.append((digest, path, kind))

        if "MPL" in package["license"]:
            mpl_components.add(key)
        checksum = lock_record["checksum"]
        components.append(
            Component(
                ecosystem="Cargo",
                name=package["name"],
                version=package["version"],
                declared_license=package["license"],
                source=(
                    "https://crates.io/api/v1/crates/"
                    f"{urllib.parse.quote(package['name'], safe='')}/"
                    f"{urllib.parse.quote(package['version'], safe='')}/download"
                ),
                integrity_label="archive SHA-256",
                integrity_value=checksum,
                authors=[clean_field(author) for author in package.get("authors", [])],
                materials=component_materials,
            )
        )

    active_package_keys = {package_key(package["name"], package["version"]) for package in packages}
    expected_active_includes = {key for key in includes if key[0] in active_package_keys}
    expected_active_excludes = {key for key in excludes if key[0] in active_package_keys}
    if used_includes != expected_active_includes:
        fail(
            "nested Cargo include decisions were not exercised exactly "
            f"(missing={sorted(expected_active_includes - used_includes)}, "
            f"extra={sorted(used_includes - expected_active_includes)})"
        )
    if used_excludes != expected_active_excludes:
        fail(
            "nested Cargo exclusion decisions were not exercised exactly "
            f"(missing={sorted(expected_active_excludes - used_excludes)}, "
            f"extra={sorted(used_excludes - expected_active_excludes)})"
        )
    expected_protocol_sources = {
        (key, path)
        for key, paths in protocol_rules.items()
        if key in active_package_keys
        for path in paths
    }
    inactive_protocol_rules = set(protocol_rules) - active_package_keys
    if inactive_protocol_rules:
        fail(
            "generated protocol source rules name packages outside the target graph: "
            f"{sorted(inactive_protocol_rules)}"
        )
    if used_protocol_sources != expected_protocol_sources:
        fail(
            "generated protocol sources were not exercised exactly "
            f"(missing={sorted(expected_protocol_sources - used_protocol_sources)}, "
            f"extra={sorted(used_protocol_sources - expected_protocol_sources)})"
        )
    expected_mpl = {
        key
        for key, license_expression in policy["mpl_source_packages"].items()
        if key in active_package_keys and license_expression
    }
    if mpl_components != expected_mpl:
        fail(
            "MPL source package set changed without review "
            f"(expected={sorted(expected_mpl)}, found={sorted(mpl_components)})"
        )
    audit = GenerationAudit(
        target=target,
        family=family,
        cargo_components=active_package_keys,
        npm_components=set(),
        rootless_components=used_fallbacks,
        nested_includes=used_includes,
        nested_excludes=used_excludes,
        protocol_sources=used_protocol_sources,
        mpl_components=mpl_components,
        material_groups=0,
    )
    return components, audit


def npm_runtime_paths(lock: dict[str, Any]) -> set[str]:
    packages = lock.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        fail("npm lock has no packages/root entry")
    root_package = packages[""]
    roots = root_package.get("dependencies")
    if not isinstance(roots, dict):
        fail("npm lock root has no runtime dependency map")
    selected: set[str] = set()
    pending = sorted(roots)
    while pending:
        name = pending.pop()
        path = f"node_modules/{name}"
        if path in selected:
            continue
        package = packages.get(path)
        if not isinstance(package, dict):
            fail(f"npm runtime dependency has no root lock entry: {name}")
        selected.add(path)
        dependencies = package.get("dependencies", {})
        if not isinstance(dependencies, dict):
            fail(f"npm runtime dependency map is malformed: {path}")
        pending.extend(sorted(dependencies))
    return selected


def npm_runtime_closure_records(lock: dict[str, Any], paths: set[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(paths):
        package = lock["packages"].get(path)
        if not isinstance(package, dict):
            fail(f"npm runtime package disappeared while proving closure: {path}")
        name = path[len("node_modules/") :]
        dependencies = package.get("dependencies", {})
        if not isinstance(dependencies, dict):
            fail(f"npm runtime dependency map is malformed: {path}")
        record = {
            "name": name,
            "version": package.get("version"),
            "license": package.get("license"),
            "resolved": package.get("resolved"),
            "integrity": package.get("integrity"),
            "dependencies": dependencies,
        }
        if not all(isinstance(record[field], str) for field in ("version", "license", "resolved", "integrity")):
            fail(f"npm runtime package lacks exact closure metadata: {path}")
        records.append(record)
    return records


def npm_components(
    policy: dict[str, Any], collector: MaterialCollector
) -> tuple[list[Component], set[str]]:
    try:
        lock = json.loads(NPM_LOCK.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"npm lock is invalid JSON: {error}")
    try:
        install_lock = json.loads(NPM_INSTALL_LOCK.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"npm ci installation receipt is absent or invalid: {error}")
    if install_lock.get("lockfileVersion") != lock.get("lockfileVersion"):
        fail("npm ci installation receipt lockfile version differs from the root lock")
    if not isinstance(install_lock.get("packages"), dict):
        fail("npm ci installation receipt has no package map")
    paths = npm_runtime_paths(lock)
    expected = policy["npm_runtime"]
    closure_records = npm_runtime_closure_records(lock, paths)
    closure_digest = canonical_json_sha256(closure_records)
    if closure_digest != policy["npm_runtime_closure_sha256"]:
        fail(
            "npm runtime closure changed without review "
            f"(expected {policy['npm_runtime_closure_sha256']}, found {closure_digest})"
        )
    found_keys: set[str] = set()
    components: list[Component] = []
    for path in sorted(paths):
        name = path[len("node_modules/") :]
        locked = lock["packages"][path]
        version = locked.get("version")
        declared_license = locked.get("license")
        if not version or not declared_license:
            fail(f"npm runtime package lacks exact version/licence metadata: {path}")
        key = package_key(name, version)
        found_keys.add(key)
        expected_package = expected.get(key)
        if not isinstance(expected_package, dict):
            fail(f"npm runtime package entered the closure without review: {key}")
        actual_package = {
            "license": declared_license,
            "resolved": locked.get("resolved"),
            "integrity": locked.get("integrity"),
            "dependencies": locked.get("dependencies", {}),
            "materials": expected_package["materials"],
        }
        if actual_package != expected_package:
            fail(f"npm runtime package metadata changed without review: {key}")
        installed_record = install_lock["packages"].get(path)
        if not isinstance(installed_record, dict):
            fail(f"npm ci installation receipt has no runtime package: {key}")
        installed_identity = {
            "version": installed_record.get("version"),
            "license": installed_record.get("license"),
            "resolved": installed_record.get("resolved"),
            "integrity": installed_record.get("integrity"),
            "dependencies": installed_record.get("dependencies", {}),
        }
        locked_identity = {
            "version": version,
            "license": declared_license,
            "resolved": locked.get("resolved"),
            "integrity": locked.get("integrity"),
            "dependencies": locked.get("dependencies", {}),
        }
        if installed_identity != locked_identity:
            fail(f"npm ci installation receipt differs from the reviewed lock: {key}")
        package_dir = NPM_MODULES / name
        manifest_path = package_dir / "package.json"
        if not manifest_path.is_file():
            fail(f"installed npm runtime package is absent: {key}; run npm ci first")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            fail(f"installed npm package manifest is invalid: {key}: {error}")
        if manifest.get("name") != name or manifest.get("version") != version:
            fail(f"installed npm package identity differs from the lock: {key}")
        if manifest.get("license") != declared_license:
            fail(f"installed npm package licence differs from the lock: {key}")
        selected_files: list[pathlib.Path] = []
        for candidate in package_dir.iterdir():
            if candidate.is_file() and root_material(candidate.name):
                selected_files.append(candidate)
        if not selected_files:
            fail(f"npm runtime package has no root licence material: {key}")
        selected_materials = {
            candidate.name: sha256_file(candidate) for candidate in selected_files
        }
        if selected_materials != expected_package["materials"]:
            fail(f"installed npm licence material changed without review: {key}")
        for candidate in package_dir.rglob("*"):
            if candidate.is_file() and candidate.parent != package_dir:
                relative = candidate.relative_to(package_dir).as_posix()
                if suspicious_nested_material(relative):
                    fail(f"npm runtime package has unreviewed nested licence material: {key} ({relative})")
        materials: list[tuple[str, str, str]] = []
        for candidate in sorted(selected_files, key=lambda item: item.name):
            kind = material_kind(candidate.name)
            digest = collector.add(candidate.read_bytes(), key, candidate.name, kind)
            materials.append((digest, candidate.name, kind))
        author = manifest.get("author")
        if isinstance(author, dict):
            author_values = [clean_field(author.get("name", ""))]
        elif author:
            author_values = [clean_field(author)]
        else:
            author_values = []
        resolved = actual_package["resolved"]
        integrity = actual_package["integrity"]
        if not isinstance(resolved, str) or not resolved.startswith("https://registry.npmjs.org/"):
            fail(f"npm runtime package has an unreviewed source: {key}")
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            fail(f"npm runtime package has no SHA-512 integrity: {key}")
        components.append(
            Component(
                ecosystem="npm",
                name=name,
                version=version,
                declared_license=declared_license,
                source=resolved,
                integrity_label="npm integrity",
                integrity_value=integrity,
                authors=[value for value in author_values if value],
                materials=materials,
            )
        )
    if found_keys != set(expected):
        fail(
            "npm runtime package set changed without review "
            f"(expected={sorted(expected)}, found={sorted(found_keys)})"
        )
    return components, found_keys


def verify_npm_bundle(policy_path: pathlib.Path) -> None:
    try:
        result = subprocess.run(
            ["node", str(NPM_BUNDLE_VERIFIER), "--policy", str(policy_path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        fail(f"dashboard bundle closure verifier could not start: {error}")
    if result.returncode != 0:
        detail = clean_field(result.stdout + result.stderr)
        fail(f"dashboard bundle closure proof failed: {detail}")
    if not result.stdout.startswith("dashboard-bundle-closure: PASS packages="):
        fail("dashboard bundle closure verifier returned no PASS receipt")


def render_document(
    target: str,
    family: str,
    policy: dict[str, Any],
    components: list[Component],
    collector: MaterialCollector,
    audit: GenerationAudit,
    policy_path: pathlib.Path,
) -> bytes:
    policy_digest = sha256_file(policy_path)
    lines = [
        "HYDRA LOCAL THIRD-PARTY LICENCES",
        "================================",
        "",
        "This target-specific artifact accompanies the Hydra Local binary distribution.",
        "Licence, copyright, NOTICE and reviewed provenance files below are copied verbatim",
        "from exact locked package archives/installations. Identical bytes are stored once,",
        "while the component attribution index retains every package and source path.",
        "",
        f"Target: {target}",
        f"Target family: {family}",
        f"Cargo.lock SHA-256: {policy['cargo_lock_sha256']}",
        f"dashboard-ui/package-lock.json SHA-256: {policy['npm_lock_sha256']}",
        f"Reviewed policy SHA-256: {policy_digest}",
        f"Cargo normal/build dependency versions: {len(audit.cargo_components)}",
        f"npm runtime dependency versions: {len(audit.npm_components)}",
        f"Deduplicated material bodies: {len(collector.groups)}",
        "",
    ]
    if family == "linux":
        lines.extend(
            [
                "LINUX WAYLAND BOUNDARY",
                "----------------------",
                "Linux uses Tao/GTK as its owner loop, and the residual winit dependency is built",
                "with its X11 backend only. The reviewed normal/build graph consumes no Wayland XML",
                "code-generation inputs and excludes wayland-client, wayland-protocols, Plasma, WLR",
                "and Smithay client-toolkit. System GTK/Wayland libraries remain represented by their",
                "ordinary FFI crates. This removes the prior Plasma classification ambiguity rather",
                "than making a legal determination about the removed generated bindings.",
                "",
            ]
        )
    lines.extend(["COMPONENT ATTRIBUTION INDEX", "---------------------------", ""])
    by_key = {package_key(component.name, component.version): component for component in components}
    for component in sorted(
        components, key=lambda item: (item.ecosystem.lower(), item.name.lower(), item.version)
    ):
        key = package_key(component.name, component.version)
        lines.extend(
            [
                f"[{component.ecosystem}] {key}",
                f"Declared licence: {clean_field(component.declared_license)}",
                f"Authors: {', '.join(component.authors) if component.authors else 'not declared in package metadata'}",
                f"Version-specific source: {component.source}",
                f"{component.integrity_label}: {component.integrity_value}",
                "Included material:",
            ]
        )
        for digest, path, kind in sorted(component.materials, key=lambda item: (item[1], item[2], item[0])):
            lines.append(f"- {digest}  {kind}  {path}")
        lines.append("")

    lines.extend(["MPL-2.0 CORRESPONDING SOURCE REFERENCES", "---------------------------------------", ""])
    if audit.mpl_components:
        for key in sorted(audit.mpl_components):
            component = by_key[key]
            lines.extend(
                [
                    f"{key}",
                    f"Source archive: {component.source}",
                    f"Archive SHA-256: {component.integrity_value}",
                    "",
                ]
            )
    else:
        lines.extend(["None for this target.", ""])

    lines.extend(["DEDUPLICATED VERBATIM MATERIAL", "------------------------------", ""])
    for digest in sorted(collector.groups):
        group = collector.groups[digest]
        lines.append(f"MATERIAL SHA-256: {digest}")
        lines.append(f"MATERIAL BYTE LENGTH: {len(group.data)}")
        lines.append("Applies to:")
        for attribution in sorted(
            group.attributions,
            key=lambda item: (item.component.lower(), item.path, item.kind),
        ):
            lines.append(
                f"- {attribution.component}  {attribution.kind}  {attribution.path}"
            )
        lines.append("----- BEGIN VERBATIM BYTES -----")
        text = group.data.decode("utf-8")
        lines.append(text[:-1] if text.endswith("\n") else text)
        lines.append("----- END VERBATIM BYTES -----")
        lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def generate(target: str, policy_path: pathlib.Path = POLICY_PATH) -> tuple[bytes, GenerationAudit]:
    policy = load_policy(policy_path)
    target_policy = policy["targets"].get(target)
    if not isinstance(target_policy, dict):
        fail(f"target is not approved by the reviewed licence policy: {target}")
    family = target_policy["family"]
    verify_npm_bundle(policy_path)
    collector = MaterialCollector()
    rust, audit = cargo_components(target, family, policy, collector)
    npm, npm_keys = npm_components(policy, collector)
    audit.npm_components = npm_keys
    audit.material_groups = len(collector.groups)
    document = render_document(
        target, family, policy, rust + npm, collector, audit, policy_path
    )
    if family == "linux":
        forbidden = (
            b"wayland-client@",
            b"wayland-protocols@",
            b"wayland-protocols-plasma@",
            b"plasma-wayland-protocols/",
            b"wayland-protocols-wlr@",
            b"wlr-protocols/",
            b"smithay-client-toolkit@",
        )
        if any(value in document for value in forbidden):
            fail("removed Linux Wayland/Plasma dependency material re-entered the artifact")
    if not document.strip():
        fail("generated third-party licence artifact is empty")
    return document, audit


def write_atomic(path: pathlib.Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False)
    temporary = pathlib.Path(handle.name)
    try:
        with handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_args(arguments: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="exact Rust target triple")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    return parser.parse_args(list(arguments))


def main(arguments: Iterable[str] = sys.argv[1:]) -> int:
    try:
        args = parse_args(arguments)
        document, audit = generate(args.target)
        write_atomic(args.output, document)
        print(
            "third-party-licenses: PASS "
            f"target={audit.target} cargo={len(audit.cargo_components)} "
            f"npm={len(audit.npm_components)} materials={audit.material_groups} "
            f"output={args.output}"
        )
        return 0
    except GenerationError as error:
        print(f"third-party-licenses: ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
