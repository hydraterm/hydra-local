#!/usr/bin/env python3
"""Verify the exact local-only package shape, provenance, and archive boundary."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import pathlib
import plistlib
import stat
import sys
import tarfile
import zlib
from dataclasses import dataclass
from typing import Iterable


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXED_MTIME = 946684800


class BoundaryError(RuntimeError):
    pass


@dataclass(frozen=True)
class PackageOptions:
    platform: str
    arch: str | None
    expected_binaries_dir: pathlib.Path
    expected_third_party_licenses: pathlib.Path
    forbidden_paths: tuple[pathlib.Path, ...] = ()


@dataclass(frozen=True)
class ExpectedFile:
    source: pathlib.Path | None
    mode: int
    role: str


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encoded_path_markers(extra_paths: Iterable[pathlib.Path] = ()) -> dict[bytes, str]:
    cargo_home = pathlib.Path(os.environ.get("CARGO_HOME", pathlib.Path.home() / ".cargo"))
    values = [
        (ROOT.resolve(), "public source root"),
        (pathlib.Path.home().resolve(), "builder home"),
        (cargo_home.resolve(), "Cargo home"),
        *((path.resolve(), "ephemeral packaging path") for path in extra_paths),
    ]
    markers: dict[bytes, str] = {}
    for value, label in sorted(values, key=lambda item: len(str(item[0])), reverse=True):
        rendered = str(value)
        if rendered in {"", "/"}:
            raise BoundaryError(f"refusing unsafe {label} marker: {rendered!r}")
        for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
            markers[rendered.encode(encoding)] = f"{label} ({encoding})"
    return markers


def scan_bytes(name: str, payload: bytes, markers: dict[bytes, str]) -> None:
    for marker, label in markers.items():
        if marker in payload:
            raise BoundaryError(f"{name} contains {label}")


def regular_source(path: pathlib.Path, role: str) -> pathlib.Path:
    path = path.resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise BoundaryError(f"expected {role} source is not a regular file: {path}")
    return path


def expected_shape(options: PackageOptions) -> tuple[str, dict[str, ExpectedFile], set[str], str]:
    binaries = options.expected_binaries_dir.resolve(strict=True)
    third_party = regular_source(options.expected_third_party_licenses, "third-party licence")
    dashboard = ROOT / "dashboard-ui/dist"
    if not dashboard.is_dir():
        raise BoundaryError("dashboard distribution is absent")
    dashboard_files = sorted(path for path in dashboard.rglob("*") if path.is_file())
    if not dashboard_files or not any(path.name == "index.html" for path in dashboard_files):
        raise BoundaryError("dashboard distribution is incomplete")
    if any(path.is_symlink() for path in dashboard.rglob("*")):
        raise BoundaryError("dashboard distribution contains a symlink")

    if options.platform == "macos":
        if options.arch is not None:
            raise BoundaryError("macOS package does not accept --arch")
        root = "Hydra.app"
        group = "wheel"
        files: dict[str, ExpectedFile] = {
            f"{root}/Contents/Info.plist": ExpectedFile(None, 0o644, "Info.plist"),
            f"{root}/Contents/MacOS/Hydra": ExpectedFile(
                regular_source(binaries / "hydra-launcher", "Hydra launcher"), 0o755, "Hydra launcher"
            ),
            f"{root}/Contents/Resources/bin/maestro-app": ExpectedFile(
                regular_source(binaries / "maestro-app", "desktop binary"), 0o755, "desktop binary"
            ),
            f"{root}/Contents/Resources/bin/pty-daemon": ExpectedFile(
                regular_source(binaries / "pty-daemon", "PTY daemon"), 0o755, "PTY daemon"
            ),
            f"{root}/Contents/Resources/licenses/LICENSE": ExpectedFile(
                regular_source(ROOT / "LICENSE", "project licence"), 0o644, "project licence"
            ),
            f"{root}/Contents/Resources/licenses/THIRD_PARTY_LICENSES.txt": ExpectedFile(
                third_party, 0o644, "third-party licences"
            ),
            f"{root}/Contents/Resources/licenses/THIRD_PARTY_NOTICES.md": ExpectedFile(
                regular_source(ROOT / "THIRD_PARTY_NOTICES.md", "third-party notices"),
                0o644,
                "third-party notices",
            ),
        }
        dashboard_prefix = f"{root}/Contents/Resources/dashboard-ui"
    elif options.platform == "linux":
        if options.arch not in {"amd64", "arm64"}:
            raise BoundaryError("Linux package requires --arch amd64 or arm64")
        root = f"hydra-local-linux-{options.arch}"
        group = "root"
        files = {
            f"{root}/bin/hydra-local": ExpectedFile(
                regular_source(ROOT / "packaging/linux/hydra-local", "Linux launcher"),
                0o755,
                "Linux launcher",
            ),
            f"{root}/bin/maestro-app": ExpectedFile(
                regular_source(binaries / "maestro-app", "desktop binary"), 0o755, "desktop binary"
            ),
            f"{root}/bin/pty-daemon": ExpectedFile(
                regular_source(binaries / "pty-daemon", "PTY daemon"), 0o755, "PTY daemon"
            ),
            f"{root}/share/licenses/LICENSE": ExpectedFile(
                regular_source(ROOT / "LICENSE", "project licence"), 0o644, "project licence"
            ),
            f"{root}/share/licenses/THIRD_PARTY_LICENSES.txt": ExpectedFile(
                third_party, 0o644, "third-party licences"
            ),
            f"{root}/share/licenses/THIRD_PARTY_NOTICES.md": ExpectedFile(
                regular_source(ROOT / "THIRD_PARTY_NOTICES.md", "third-party notices"),
                0o644,
                "third-party notices",
            ),
        }
        dashboard_prefix = f"{root}/dashboard-ui"
    else:
        raise BoundaryError(f"unsupported package platform: {options.platform}")

    for source in dashboard_files:
        relative = source.relative_to(dashboard).as_posix()
        files[f"{dashboard_prefix}/{relative}"] = ExpectedFile(source.resolve(), 0o644, "dashboard asset")

    directories = {root}
    for name in files:
        parent = pathlib.PurePosixPath(name).parent
        while parent.as_posix() not in {".", ""}:
            directories.add(parent.as_posix())
            if parent.as_posix() == root:
                break
            parent = parent.parent
    return root, files, directories, group


def expected_info_plist() -> bytes:
    version = ""
    manifest = ROOT / "maestro-app/Cargo.toml"
    for line in manifest.read_text(encoding="utf-8").splitlines():
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


def validate_info_plist(payload: bytes) -> None:
    try:
        document = plistlib.loads(payload)
    except Exception as error:
        raise BoundaryError(f"Info.plist is invalid: {error}") from error
    expected_document = plistlib.loads(expected_info_plist())
    if document != expected_document:
        raise BoundaryError("Info.plist differs from the reviewed source-build contract")
    if payload != expected_info_plist():
        raise BoundaryError("Info.plist bytes differ from the canonical source-build contract")


def canonical_tar_payload(
    root: str,
    files: dict[str, ExpectedFile],
    directories: set[str],
    group: str,
) -> bytes:
    output = io.BytesIO()
    names = [root, *sorted((directories - {root}) | set(files))]
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as bundle:
        for name in names:
            if name in directories:
                info = tarfile.TarInfo(name + "/")
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                payload = None
            else:
                expected = files[name]
                content = (
                    expected_info_plist()
                    if expected.source is None
                    else expected.source.read_bytes()
                )
                info = tarfile.TarInfo(name)
                info.type = tarfile.REGTYPE
                info.mode = expected.mode
                info.size = len(content)
                payload = io.BytesIO(content)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = group
            info.mtime = FIXED_MTIME
            bundle.addfile(info, payload)
    return output.getvalue()


def canonical_gzip_payload(payload: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, compresslevel=9, mtime=0) as zipped:
        zipped.write(payload)
    return output.getvalue()


def verify_gzip_frame(path: pathlib.Path) -> bytes:
    canonical_header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    decompressed = bytearray()
    try:
        with path.open("rb") as archive_stream:
            header = archive_stream.read(len(canonical_header))
            if header != canonical_header:
                raise BoundaryError("gzip header differs from the canonical release encoding")
            decompressed.extend(decompressor.decompress(header))
            for chunk in iter(lambda: archive_stream.read(1024 * 1024), b""):
                decompressed.extend(decompressor.decompress(chunk))
                if decompressor.unused_data:
                    raise BoundaryError("gzip stream has trailing or concatenated bytes")
                if decompressor.eof:
                    if archive_stream.read(1):
                        raise BoundaryError("gzip stream has trailing or concatenated bytes")
                    break
            decompressed.extend(decompressor.flush())
    except zlib.error as error:
        raise BoundaryError(f"gzip stream is invalid: {error}") from error
    if not decompressor.eof:
        raise BoundaryError("gzip stream is incomplete")
    if decompressor.unused_data:
        raise BoundaryError("gzip stream has trailing or concatenated bytes")
    return bytes(decompressed)


def verify_tar_padding(payload: bytes, members: list[tarfile.TarInfo]) -> None:
    if not members:
        raise BoundaryError("package tar stream contains no members")
    block_size = tarfile.BLOCKSIZE
    record_size = tarfile.RECORDSIZE
    payload_end = 0
    for member in members:
        data_end = member.offset_data + member.size
        padded_end = ((data_end + block_size - 1) // block_size) * block_size
        if any(payload[data_end:padded_end]):
            raise BoundaryError(f"tar member has non-zero data padding: {member.name}")
        payload_end = max(payload_end, padded_end)
    minimum_end = payload_end + (2 * block_size)
    canonical_end = ((minimum_end + record_size - 1) // record_size) * record_size
    if len(payload) != canonical_end:
        raise BoundaryError("tar stream has non-canonical EOF or trailing payload")
    if any(payload[payload_end:]):
        raise BoundaryError("tar EOF and record padding are not all zero")


def scan_archive(path: pathlib.Path, options: PackageOptions) -> int:
    if not path.is_file():
        raise BoundaryError(f"package archive does not exist: {path}")
    tar_payload = verify_gzip_frame(path)
    root, expected_files, expected_directories, group = expected_shape(options)
    markers = encoded_path_markers(options.forbidden_paths)
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    seen: set[str] = set()
    info_plist: bytes | None = None
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:") as archive:
            if archive.pax_headers:
                raise BoundaryError("archive contains unreviewed global PAX metadata")
            members = archive.getmembers()
            verify_tar_padding(tar_payload, members)
            for member in members:
                name = member.name.rstrip("/")
                pure = pathlib.PurePosixPath(name)
                if not name or pure.is_absolute() or ".." in pure.parts:
                    raise BoundaryError(f"archive contains an unsafe member path: {member.name}")
                if name in seen:
                    raise BoundaryError(f"archive contains a duplicate member: {name}")
                seen.add(name)
                if pure.parts[0] != root:
                    raise BoundaryError(f"archive contains an unexpected root: {name}")
                scan_bytes(f"archive member name {name}", name.encode("utf-8"), markers)
                if member.uid != 0 or member.gid != 0:
                    raise BoundaryError(f"archive member has non-root numeric ownership: {name}")
                if member.uname != "root" or member.gname != group:
                    raise BoundaryError(f"archive member has unreviewed owner names: {name}")
                if member.mtime != FIXED_MTIME:
                    raise BoundaryError(f"archive member has non-reproducible timestamp: {name}")
                if member.pax_headers:
                    raise BoundaryError(f"archive member carries unreviewed PAX metadata: {name}")
                if member.issym() or member.islnk():
                    raise BoundaryError(f"archive contains an unreviewed link: {name}")
                if member.isdir():
                    if stat.S_IMODE(member.mode) != 0o755:
                        raise BoundaryError(f"archive directory has unexpected mode: {name}")
                    observed_directories.add(name)
                    continue
                if not member.isfile():
                    raise BoundaryError(f"archive contains a special member: {name}")
                if pure.name == "hydra-agent":
                    raise BoundaryError(f"archive contains the private agent executable: {name}")
                expected = expected_files.get(name)
                if expected is None:
                    raise BoundaryError(f"archive contains an unexpected file: {name}")
                if stat.S_IMODE(member.mode) != expected.mode:
                    raise BoundaryError(f"archive file has unexpected mode: {name}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise BoundaryError(f"archive member cannot be read: {name}")
                digest = hashlib.sha256()
                captured = bytearray()
                longest_marker = max(map(len, markers), default=1)
                overlap = b""
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    scan_bytes(name, overlap + chunk, markers)
                    overlap = (overlap + chunk)[-(longest_marker - 1) :] if longest_marker > 1 else b""
                    digest.update(chunk)
                    if expected.source is None:
                        captured.extend(chunk)
                if expected.source is not None and digest.hexdigest() != sha256_file(expected.source):
                    raise BoundaryError(f"archive {expected.role} differs from its exact source: {name}")
                if expected.source is None:
                    info_plist = bytes(captured)
                observed_files.add(name)
    except (OSError, tarfile.TarError) as error:
        raise BoundaryError(f"cannot inspect package archive: {error}") from error

    missing_files = sorted(set(expected_files) - observed_files)
    extra_directories = sorted(observed_directories - expected_directories)
    missing_directories = sorted(expected_directories - observed_directories)
    if missing_files:
        raise BoundaryError(f"archive is missing required files: {', '.join(missing_files)}")
    if extra_directories:
        raise BoundaryError(f"archive contains unexpected directories: {', '.join(extra_directories)}")
    if missing_directories:
        raise BoundaryError(f"archive is missing required directories: {', '.join(missing_directories)}")
    if options.platform == "macos":
        if info_plist is None:
            raise BoundaryError("archive is missing Info.plist")
        validate_info_plist(info_plist)
    canonical = canonical_tar_payload(root, expected_files, expected_directories, group)
    if tar_payload != canonical:
        raise BoundaryError("tar stream differs from its byte-exact canonical serialization")
    if path.read_bytes() != canonical_gzip_payload(canonical):
        raise BoundaryError("archive differs from its byte-exact canonical gzip serialization")
    return len(observed_files)


def parse_args(arguments: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--platform", required=True, choices=("macos", "linux"))
    parser.add_argument("--arch", choices=("amd64", "arm64"))
    parser.add_argument("--expected-binaries-dir", required=True, type=pathlib.Path)
    parser.add_argument("--expected-third-party-licenses", required=True, type=pathlib.Path)
    parser.add_argument("--forbidden-path", action="append", default=[], type=pathlib.Path)
    return parser.parse_args(list(arguments))


def main(arguments: Iterable[str] = sys.argv[1:]) -> int:
    try:
        args = parse_args(arguments)
        options = PackageOptions(
            platform=args.platform,
            arch=args.arch,
            expected_binaries_dir=args.expected_binaries_dir,
            expected_third_party_licenses=args.expected_third_party_licenses,
            forbidden_paths=tuple(args.forbidden_path),
        )
        count = scan_archive(args.archive, options)
        print(
            f"packaged-boundary: PASS platform={args.platform} files={count} "
            f"archive={args.archive}"
        )
        return 0
    except BoundaryError as error:
        print(f"packaged-boundary: ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
