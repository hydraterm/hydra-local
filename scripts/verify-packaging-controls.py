#!/usr/bin/env python3
"""Adversarial and reproducibility tests for the unsigned package path."""

from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import os
import pathlib
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "scripts/verify-packaged-boundary.py"
CREATOR = ROOT / "scripts/create-reproducible-tar.py"
PROOFS: list[str] = []


def load_module(name: str, path: pathlib.Path):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"packaging-control-tests: cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def pass_proof(name: str) -> None:
    PROOFS.append(name)
    print(f"packaging-control-tests: PASS {name}")


def exact_plist() -> bytes:
    version = ""
    for line in (ROOT / "maestro-app/Cargo.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version = \""):
            version = line.split('"', 2)[1]
            break
    build_number = version.replace(".", "")
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDisplayName</key><string>Hydra</string>
  <key>CFBundleExecutable</key><string>Hydra</string>
  <key>CFBundleIdentifier</key><string>com.hydraterms.hydra.source-build</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>Hydra</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>{version}</string>
  <key>CFBundleVersion</key><string>{build_number}</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
</dict></plist>
'''.encode()


def fixture(
    verifier,
    creator,
    directory: pathlib.Path,
    *,
    platform: str = "macos",
    arch: str | None = None,
):
    directory.mkdir(parents=True)
    binaries = directory / "binaries"
    binaries.mkdir()
    for name in ("hydra-launcher", "maestro-app", "pty-daemon"):
        (binaries / name).write_bytes(f"exact-{name}\n".encode())
    third_party = directory / "THIRD_PARTY_LICENSES.txt"
    third_party.write_text("exact generated third-party licences\n", encoding="utf-8")
    options = verifier.PackageOptions(platform, arch, binaries, third_party)
    root_name, files, _, group = verifier.expected_shape(options)
    package_root = directory / root_name
    for name, expected in files.items():
        destination = directory / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if expected.source is None:
            destination.write_bytes(exact_plist())
        else:
            shutil.copyfile(expected.source, destination)
        destination.chmod(expected.mode)
    archive = directory / "package.tar.gz"
    creator.create(package_root, archive, group)
    return archive, options, package_root


def expect_failure(verifier, path: pathlib.Path, options, expected: str, name: str) -> None:
    try:
        verifier.scan_archive(path, options)
    except verifier.BoundaryError as error:
        if expected not in str(error):
            raise AssertionError(f"{name}: unexpected error: {error}") from error
        pass_proof(name)
    else:
        raise AssertionError(f"{name}: archive unexpectedly passed")


def deterministic_tar(path: pathlib.Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    with path.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, compresslevel=9, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as bundle:
                for info, payload in members:
                    bundle.addfile(info, io.BytesIO(payload) if info.isfile() else None)


def canonical_gzip(payload: bytes, *, compresslevel: int = 9) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=output, compresslevel=compresslevel, mtime=0
    ) as zipped:
        zipped.write(payload)
    return output.getvalue()


def rewrite_archive(
    source: pathlib.Path,
    destination: pathlib.Path,
    transform,
) -> None:
    members: list[tuple[tarfile.TarInfo, bytes]] = []
    with tarfile.open(source, mode="r:gz") as bundle:
        for original in bundle.getmembers():
            info = copy.copy(original)
            stream = bundle.extractfile(original) if original.isfile() else None
            payload = stream.read() if stream is not None else b""
            transformed = transform(info, payload)
            if transformed is not None:
                members.append(transformed)
    deterministic_tar(destination, members)


def make_executable(path: pathlib.Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def copy_release_fixture(root: pathlib.Path) -> None:
    for relative in (
        ".nvmrc",
        ".python-version",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "dashboard-ui/package.json",
        "maestro-app/Cargo.toml",
        "packaging/linux/hydra-local",
        "packaging/linux/package-unsigned.sh",
        "packaging/macos/package-unsigned.sh",
        "scripts/build-local.sh",
        "scripts/configure-release-path-remap.sh",
        "scripts/create-reproducible-tar.py",
        "scripts/require-python-version.sh",
        "scripts/ensure-open-file-limit.sh",
        "scripts/test-open-file-limit.sh",
        "scripts/test-local.sh",
        "scripts/verify-packaged-boundary.py",
    ):
        source = ROOT / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    shutil.copytree(ROOT / "dashboard-ui/dist", root / "dashboard-ui/dist")


def seed_stale_dashboard(root: pathlib.Path) -> None:
    dashboard = root / "dashboard-ui"
    distribution = dashboard / "dist"
    shutil.rmtree(distribution, ignore_errors=True)
    distribution.mkdir(parents=True)
    (distribution / "index.html").write_text("STALE-DASHBOARD\n", encoding="utf-8")
    (distribution / "stale-only.js").write_text("STALE-DASHBOARD\n", encoding="utf-8")
    for marker in (dashboard / ".fake-npm-ci", dashboard / ".fake-npm-log"):
        marker.unlink(missing_ok=True)
    for marker in (
        root / ".fake-cargo-invoked",
        root / ".fake-node-invoked",
        root / ".fake-npm-invoked",
    ):
        marker.unlink(missing_ok=True)


def fake_toolchain(directory: pathlib.Path, fixture_root: pathlib.Path) -> pathlib.Path:
    tools = directory / "tools"
    tools.mkdir(parents=True)
    make_executable(
        tools / "uname",
        "#!/bin/sh\n"
        "case \"${1:-}\" in -s) printf '%s\\n' \"$FAKE_UNAME_S\";; "
        "-m) printf '%s\\n' \"$FAKE_UNAME_M\";; *) exit 2;; esac\n",
    )
    make_executable(
        tools / "rustc",
        "#!/bin/sh\n"
        "[ \"${1:-}\" = -vV ] || exit 2\n"
        "printf 'rustc 1.96.0\\nbinary: rustc\\nhost: %s\\n' \"$FAKE_RUST_TARGET\"\n",
    )
    make_executable(
        tools / "plutil",
        "#!/bin/sh\nset -eu\n"
        "[ \"$#\" -eq 2 ] && [ \"$1\" = -lint ] && [ -s \"$2\" ] || exit 77\n"
        "grep -q '<plist version=\"1.0\">' \"$2\" || exit 78\n"
        "printf '%s\\n' \"$2\" > \"$HYDRA_FIXTURE_ROOT/.fake-plutil-log\"\n",
    )
    make_executable(
        tools / "node",
        "#!/bin/sh\n"
        ": > \"$HYDRA_FIXTURE_ROOT/.fake-node-invoked\"\n"
        "if [ \"${1:-}\" = --version ]; then echo v22.23.1; "
        "elif [ \"${1:-}\" = -p ]; then echo 10.9.8; else exit 2; fi\n",
    )
    make_executable(
        tools / "npm",
        "#!/bin/sh\nset -eu\n"
        ": > \"$HYDRA_FIXTURE_ROOT/.fake-npm-invoked\"\n"
        "if [ \"${1:-}\" = --version ]; then echo 10.9.8; exit 0; fi\n"
        "[ \"${1:-}\" = --prefix ] && [ $# -ge 3 ] || exit 73\n"
        "prefix=$2\nshift 2\n"
        "case \"$1:${2:-}\" in\n"
        "ci:)\n"
        "  [ $# -eq 1 ] || exit 74\n"
        "  : > \"$prefix/.fake-npm-ci\"\n"
        "  printf 'ci\\n' > \"$prefix/.fake-npm-log\";;\n"
        "run:build)\n"
        "  [ $# -eq 2 ] && [ -f \"$prefix/.fake-npm-ci\" ] || exit 75\n"
        "  rm -rf \"$prefix/dist\"\n"
        "  mkdir -p \"$prefix/dist/assets\"\n"
        "  printf '<html>FRESH-DASHBOARD</html>\\n' > \"$prefix/dist/index.html\"\n"
        "  printf 'FRESH-DASHBOARD-CSS\\n' > \"$prefix/dist/assets/index-fresh.css\"\n"
        "  printf 'FRESH-DASHBOARD-JS\\n' > \"$prefix/dist/assets/index-fresh.js\"\n"
        "  chmod 0775 \"$prefix/dist\" \"$prefix/dist/assets\"\n"
        "  chmod 0664 \"$prefix/dist/index.html\" \"$prefix/dist/assets/index-fresh.css\" "
        "\"$prefix/dist/assets/index-fresh.js\"\n"
        "  printf 'build\\n' >> \"$prefix/.fake-npm-log\";;\n"
        "*) exit 76;;\n"
        "esac\n",
    )
    make_executable(
        tools / "cargo",
        "#!/bin/sh\n"
        "set -eu\n"
        ": > \"$HYDRA_FIXTURE_ROOT/.fake-cargo-invoked\"\n"
        ": \"${CARGO_TARGET_DIR:?missing isolated target directory}\"\n"
        "case \"$CARGO_TARGET_DIR\" in \"$HYDRA_FIXTURE_ROOT/target\"*) exit 70;; esac\n"
        "target=\nprevious=\n"
        "for argument in \"$@\"; do "
        "if [ \"$previous\" = --target ]; then target=$argument; fi; previous=$argument; done\n"
        "[ \"$target\" = \"$FAKE_RUST_TARGET\" ] || exit 71\n"
        "release=$CARGO_TARGET_DIR/$target/release\nmkdir -p \"$release\"\n"
        "for binary in hydra-launcher maestro-app pty-daemon; do "
        "printf 'fresh:%s:%s\\n' \"$target\" \"$binary\" > \"$release/$binary\"; "
        "chmod 755 \"$release/$binary\"; done\n",
    )
    real_python = shlex.quote(sys.executable)
    make_executable(
        tools / "python3",
        "#!/bin/sh\nset -eu\n"
        "if [ \"${1:-}\" = -c ] && [ -n \"${FAKE_PYTHON_VERSION:-}\" ]; then "
        "printf 'CPython %s\\n' \"$FAKE_PYTHON_VERSION\"; exit 0; fi\n"
        "case \"${1##*/}\" in\n"
        "generate-third-party-licenses.py)\n"
        "  shift; output=\n"
        "  while [ $# -gt 0 ]; do "
        "if [ \"$1\" = --output ]; then shift; output=$1; fi; shift; done\n"
        "  [ -n \"$output\" ] || exit 72\n"
        "  printf 'fixture third-party licences\\n' > \"$output\";;\n"
        f"*) exec {real_python} \"$@\";;\n"
        "esac\n",
    )
    return tools


def run_fixture_package(
    fixture_root: pathlib.Path,
    tools: pathlib.Path,
    output: pathlib.Path,
    platform: str,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    seed_stale_dashboard(fixture_root)
    if platform == "macos":
        script = fixture_root / "packaging/macos/package-unsigned.sh"
        system, machine, target = "Darwin", "arm64", "aarch64-apple-darwin"
    else:
        script = fixture_root / "packaging/linux/package-unsigned.sh"
        system, machine, target = "Linux", "x86_64", "x86_64-unknown-linux-gnu"
    environment = os.environ.copy()
    for name in (
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "PATH": f"{tools}:{environment['PATH']}",
            "FAKE_UNAME_S": system,
            "FAKE_UNAME_M": machine,
            "FAKE_RUST_TARGET": target,
            "HYDRA_FIXTURE_ROOT": str(fixture_root),
        }
    )
    environment.update(extra_env or {})
    return subprocess.run(
        [str(script), str(output)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
        timeout=60,
        check=False,
    )


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    verifier = load_module("hydra_packaged_boundary", VERIFIER)
    creator = load_module("hydra_reproducible_tar", CREATOR)
    with tempfile.TemporaryDirectory(prefix="hydra-packaging-controls-") as directory:
        temporary = pathlib.Path(directory)

        mac_archive, mac_options, mac_root = fixture(
            verifier, creator, temporary / "valid-mac", platform="macos"
        )
        mac_count = verifier.scan_archive(mac_archive, mac_options)
        if mac_count < 8:
            raise AssertionError(f"exact macOS package file count is unexpectedly low: {mac_count}")
        pass_proof("exact macOS package shape and source bytes pass")

        linux_archive, linux_options, _ = fixture(
            verifier, creator, temporary / "valid-linux", platform="linux", arch="amd64"
        )
        linux_count = verifier.scan_archive(linux_archive, linux_options)
        if linux_count < 8:
            raise AssertionError(f"exact Linux package file count is unexpectedly low: {linux_count}")
        pass_proof("exact Linux package shape and source bytes pass")

        missing_tree = temporary / "missing-tree"
        shutil.copytree(mac_root, missing_tree / mac_root.name)
        (missing_tree / mac_root.name / "Contents/Resources/licenses/THIRD_PARTY_LICENSES.txt").unlink()
        missing_archive = missing_tree / "missing.tar.gz"
        creator.create(missing_tree / mac_root.name, missing_archive, "wheel")
        expect_failure(
            verifier,
            missing_archive,
            mac_options,
            "missing required files",
            "missing THIRD_PARTY_LICENSES fails closed",
        )

        extra_tree = temporary / "extra-tree"
        shutil.copytree(mac_root, extra_tree / mac_root.name)
        (extra_tree / mac_root.name / "Contents/Resources/unreviewed.txt").write_text("extra")
        extra_archive = extra_tree / "extra.tar.gz"
        creator.create(extra_tree / mac_root.name, extra_archive, "wheel")
        expect_failure(
            verifier, extra_archive, mac_options, "unexpected file", "unreviewed package file fails closed"
        )

        private_tree = temporary / "private-tree"
        shutil.copytree(mac_root, private_tree / mac_root.name)
        private_agent = private_tree / mac_root.name / "Contents/Resources/bin/hydra-agent"
        private_agent.write_bytes(b"private")
        private_agent.chmod(0o755)
        private_archive = private_tree / "private.tar.gz"
        creator.create(private_tree / mac_root.name, private_archive, "wheel")
        expect_failure(
            verifier,
            private_archive,
            mac_options,
            "private agent executable",
            "private agent executable fails closed",
        )

        wrong_binary_tree = temporary / "wrong-binary-tree"
        shutil.copytree(mac_root, wrong_binary_tree / mac_root.name)
        (wrong_binary_tree / mac_root.name / "Contents/Resources/bin/maestro-app").write_bytes(b"stale")
        wrong_binary_archive = wrong_binary_tree / "wrong-binary.tar.gz"
        creator.create(wrong_binary_tree / mac_root.name, wrong_binary_archive, "wheel")
        expect_failure(
            verifier,
            wrong_binary_archive,
            mac_options,
            "differs from its exact source",
            "stale binary bytes fail closed",
        )

        wrong_dashboard_tree = temporary / "wrong-dashboard-tree"
        shutil.copytree(mac_root, wrong_dashboard_tree / mac_root.name)
        dashboard_index = wrong_dashboard_tree / mac_root.name / "Contents/Resources/dashboard-ui/index.html"
        dashboard_index.write_bytes(b"stale dashboard")
        wrong_dashboard_archive = wrong_dashboard_tree / "wrong-dashboard.tar.gz"
        creator.create(wrong_dashboard_tree / mac_root.name, wrong_dashboard_archive, "wheel")
        expect_failure(
            verifier,
            wrong_dashboard_archive,
            mac_options,
            "dashboard asset differs",
            "stale dashboard bytes fail closed",
        )

        wrong_licence_tree = temporary / "wrong-licence-tree"
        shutil.copytree(mac_root, wrong_licence_tree / mac_root.name)
        generated_licences = (
            wrong_licence_tree
            / mac_root.name
            / "Contents/Resources/licenses/THIRD_PARTY_LICENSES.txt"
        )
        generated_licences.write_bytes(b"stale generated licences")
        wrong_licence_archive = wrong_licence_tree / "wrong-licence.tar.gz"
        creator.create(wrong_licence_tree / mac_root.name, wrong_licence_archive, "wheel")
        expect_failure(
            verifier,
            wrong_licence_archive,
            mac_options,
            "third-party licences differs",
            "stale generated third-party licences fail closed",
        )

        path_tree = temporary / "path-tree"
        shutil.copytree(mac_root, path_tree / mac_root.name)
        path_binary = path_tree / mac_root.name / "Contents/Resources/bin/maestro-app"
        path_binary.write_bytes(str(ROOT.resolve()).encode())
        mac_options.expected_binaries_dir.joinpath("maestro-app").write_bytes(str(ROOT.resolve()).encode())
        path_archive = path_tree / "path.tar.gz"
        creator.create(path_tree / mac_root.name, path_archive, "wheel")
        expect_failure(
            verifier,
            path_archive,
            mac_options,
            "public source root",
            "builder path in binary bytes fails closed",
        )
        mac_options.expected_binaries_dir.joinpath("maestro-app").write_bytes(b"exact-maestro-app\n")

        timestamp_archive = temporary / "timestamp.tar.gz"
        rewrite_archive(
            mac_archive,
            timestamp_archive,
            lambda info, payload: (
                (setattr(info, "mtime", verifier.FIXED_MTIME + 1) or info),
                payload,
            ),
        )
        expect_failure(
            verifier,
            timestamp_archive,
            mac_options,
            "non-reproducible timestamp",
            "variable member timestamp fails closed",
        )

        wrong_mode_archive = temporary / "wrong-mode.tar.gz"
        def wrong_mode(info, payload):
            if info.name.rstrip("/").endswith("/maestro-app"):
                info.mode = 0o777
            return info, payload
        rewrite_archive(mac_archive, wrong_mode_archive, wrong_mode)
        expect_failure(
            verifier,
            wrong_mode_archive,
            mac_options,
            "unexpected mode",
            "unreviewed executable mode fails closed",
        )

        symlink_archive = temporary / "symlink.tar.gz"
        def make_link(info, payload):
            if info.name.rstrip("/").endswith("/maestro-app"):
                info.type = tarfile.SYMTYPE
                info.linkname = "pty-daemon"
                info.size = 0
                return info, b""
            return info, payload
        rewrite_archive(mac_archive, symlink_archive, make_link)
        expect_failure(
            verifier, symlink_archive, mac_options, "unreviewed link", "archive symlink fails closed"
        )

        trailing_archive = temporary / "trailing.tar.gz"
        trailing_archive.write_bytes(mac_archive.read_bytes() + b"trailing")
        expect_failure(
            verifier,
            trailing_archive,
            mac_options,
            "trailing or concatenated bytes",
            "trailing gzip bytes fail closed",
        )

        concatenated_archive = temporary / "concatenated.tar.gz"
        concatenated_archive.write_bytes(mac_archive.read_bytes() + mac_archive.read_bytes())
        expect_failure(
            verifier,
            concatenated_archive,
            mac_options,
            "trailing or concatenated bytes",
            "concatenated gzip member fails closed",
        )

        pax_archive = temporary / "pax.tar.gz"
        def add_pax(info, payload):
            if info.name.rstrip("/").endswith("/maestro-app"):
                info.pax_headers = {"comment": "unreviewed"}
            return info, payload
        rewrite_archive(mac_archive, pax_archive, add_pax)
        expect_failure(
            verifier,
            pax_archive,
            mac_options,
            "unreviewed PAX metadata",
            "arbitrary PAX metadata fails closed",
        )

        header_archive = temporary / "header.tar.gz"
        header_bytes = bytearray(mac_archive.read_bytes())
        header_bytes[8] = 0
        header_bytes[9] = 3
        header_archive.write_bytes(header_bytes)
        expect_failure(
            verifier,
            header_archive,
            mac_options,
            "canonical release encoding",
            "modified gzip XFL and OS bytes fail closed",
        )

        post_eof_archive = temporary / "post-eof.tar.gz"
        decompressed_tar = gzip.decompress(mac_archive.read_bytes())
        post_eof_archive.write_bytes(
            canonical_gzip(decompressed_tar + b"PRIVATE-IN-GZIP-AFTER-TAR-EOF")
        )
        expect_failure(
            verifier,
            post_eof_archive,
            mac_options,
            "non-canonical EOF or trailing payload",
            "payload after canonical tar EOF fails closed",
        )

        raw_header_archive = temporary / "raw-header-padding.tar.gz"
        raw_tar = bytearray(gzip.decompress(mac_archive.read_bytes()))
        raw_tar[500:512] = b"PRIVATE-HDR!"
        raw_tar[148:156] = b"        "
        checksum = sum(raw_tar[:512])
        raw_tar[148:156] = f"{checksum:06o}\0 ".encode("ascii")
        raw_header_archive.write_bytes(canonical_gzip(bytes(raw_tar)))
        expect_failure(
            verifier,
            raw_header_archive,
            mac_options,
            "byte-exact canonical serialization",
            "unused USTAR header bytes fail closed after checksum repair",
        )

        alternate_deflate_archive = temporary / "alternate-deflate.tar.gz"
        alternate_deflate = bytearray(canonical_gzip(decompressed_tar, compresslevel=1))
        alternate_deflate[8] = 2
        if bytes(alternate_deflate[:10]) != b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff":
            raise AssertionError("alternative DEFLATE fixture does not carry the canonical header")
        alternate_deflate_archive.write_bytes(alternate_deflate)
        expect_failure(
            verifier,
            alternate_deflate_archive,
            mac_options,
            "byte-exact canonical gzip serialization",
            "alternative DEFLATE stream with canonical header fails closed",
        )

        deterministic_one = temporary / "deterministic-one.tar.gz"
        deterministic_two = temporary / "deterministic-two.tar.gz"
        creator.create(mac_root, deterministic_one, "wheel")
        creator.create(mac_root, deterministic_two, "wheel")
        if sha256(deterministic_one) != sha256(deterministic_two):
            raise AssertionError("reproducible archive helper emitted different bytes")
        pass_proof("reproducible archive helper is byte-stable across two builds")

        umask_tree = temporary / "umask-tree"
        shutil.copytree(mac_root, umask_tree / mac_root.name)
        for directory, dirnames, _ in os.walk(umask_tree / mac_root.name):
            pathlib.Path(directory).chmod(0o775)
            for dirname in dirnames:
                (pathlib.Path(directory) / dirname).chmod(0o775)
        umask_archive = temporary / "umask-normalized.tar.gz"
        creator.create(umask_tree / mac_root.name, umask_archive, "wheel")
        verifier.scan_archive(umask_archive, mac_options)
        if sha256(mac_archive) != sha256(umask_archive):
            raise AssertionError("builder umask changed canonical package bytes")
        pass_proof("builder directory umask is normalized to canonical package bytes")

        release_fixture = temporary / "release-fixture"
        copy_release_fixture(release_fixture)
        stale = release_fixture / "target/release"
        stale.mkdir(parents=True)
        for name in ("hydra-launcher", "maestro-app", "pty-daemon"):
            (stale / name).write_bytes(f"STALE:{name}\n".encode())
        tools = fake_toolchain(temporary / "fake-toolchain", release_fixture)
        for platform, archive_name in (
            ("macos", "hydra-local-macos-unsigned.tar.gz"),
            ("linux", "hydra-local-linux-amd64.tar.gz"),
        ):
            outputs = []
            for iteration in (1, 2):
                output = temporary / f"real-{platform}-{iteration}"
                result = run_fixture_package(release_fixture, tools, output, platform)
                if result.returncode != 0:
                    raise AssertionError(f"{platform} package fixture failed:\n{result.stdout}")
                outputs.append(output / archive_name)
            if sha256(outputs[0]) != sha256(outputs[1]):
                raise AssertionError(f"{platform} real package script is not byte-stable")
            with gzip.open(outputs[0], "rb") as stream:
                payload = stream.read()
            if (
                b"STALE:" in payload
                or b"fresh:" not in payload
                or b"STALE-DASHBOARD" in payload
                or b"FRESH-DASHBOARD" not in payload
            ):
                raise AssertionError(f"{platform} package did not use the fresh isolated target")
            npm_log = release_fixture / "dashboard-ui/.fake-npm-log"
            if npm_log.read_text(encoding="utf-8") != "ci\nbuild\n":
                raise AssertionError(f"{platform} package did not run npm ci then npm build")
            if platform == "macos":
                plutil_log = release_fixture / ".fake-plutil-log"
                if (
                    not plutil_log.is_file()
                    or not plutil_log.read_text(encoding="utf-8").rstrip().endswith(
                        "/Hydra.app/Contents/Info.plist"
                    )
                ):
                    raise AssertionError("macOS package did not lint its generated Info.plist")
            pass_proof(
                f"{platform} package replaces stale binary and dashboard outputs and reproduces exact bytes"
            )

            rejected_python_output = temporary / f"reject-{platform}-python"
            rejected_python = run_fixture_package(
                release_fixture,
                tools,
                rejected_python_output,
                platform,
                extra_env={"FAKE_PYTHON_VERSION": "3.9.6"},
            )
            invoked_markers = sorted(release_fixture.glob(".fake-*-invoked"))
            if (
                rejected_python.returncode == 0
                or "CPython 3.13.15 is required (found CPython 3.9.6)."
                not in rejected_python.stdout
                or rejected_python_output.exists()
                or invoked_markers
                or (release_fixture / "dashboard-ui/.fake-npm-log").exists()
            ):
                raise AssertionError(
                    f"{platform} package did not reject an unpinned Python before build work:\n"
                    + rejected_python.stdout
                )
            pass_proof(
                f"{platform} package rejects an unpinned Python before build work"
            )

            for variable in ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET"):
                rejected = run_fixture_package(
                    release_fixture,
                    tools,
                    temporary / f"reject-{platform}-{variable}",
                    platform,
                    extra_env={variable: "/tmp/unreviewed-target"},
                )
                if rejected.returncode == 0 or "refuses external Cargo target selection" not in rejected.stdout:
                    raise AssertionError(f"{platform} package accepted external {variable}:\n{rejected.stdout}")
                pass_proof(f"{platform} package rejects external {variable}")

        seed_stale_dashboard(release_fixture)
        test_environment = os.environ.copy()
        test_environment.update(
            {
                "PATH": f"{tools}:{test_environment['PATH']}",
                "FAKE_PYTHON_VERSION": "3.9.6",
                "HYDRA_FIXTURE_ROOT": str(release_fixture),
            }
        )
        rejected_test_local = subprocess.run(
            [str(release_fixture / "scripts/test-local.sh")],
            cwd=release_fixture,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=test_environment,
            timeout=10,
            check=False,
        )
        invoked_markers = sorted(release_fixture.glob(".fake-*-invoked"))
        if (
            rejected_test_local.returncode == 0
            or "CPython 3.13.15 is required (found CPython 3.9.6)."
            not in rejected_test_local.stdout
            or invoked_markers
            or (release_fixture / "dashboard-ui/.fake-npm-log").exists()
        ):
            raise AssertionError(
                "test-local did not reject an unpinned Python before build work:\n"
                + rejected_test_local.stdout
            )
        pass_proof("test-local rejects an unpinned Python before build work")

    expected_proofs = 30
    if len(PROOFS) != expected_proofs:
        raise AssertionError(f"expected {expected_proofs} packaging proofs, observed {len(PROOFS)}")
    print(f"packaging-control-tests: PASS exact proof count is {expected_proofs}")
    print(f"packaging-control-tests: RESULT pass proofs={expected_proofs + 1}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
