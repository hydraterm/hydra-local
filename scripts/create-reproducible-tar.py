#!/usr/bin/env python3
"""Create a byte-stable gzip-compressed tar archive from one package root."""

from __future__ import annotations

import argparse
import gzip
import os
import pathlib
import stat
import tarfile
import tempfile


FIXED_MTIME = 946684800


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source", required=True, type=pathlib.Path)
    result.add_argument("--archive", required=True, type=pathlib.Path)
    result.add_argument("--group-name", required=True, choices=("root", "wheel"))
    return result


def archive_info(path: pathlib.Path, name: str, group_name: str) -> tarfile.TarInfo:
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode):
        raise ValueError(f"package source contains a symlink: {path}")
    info = tarfile.TarInfo(name + ("/" if stat.S_ISDIR(status.st_mode) else ""))
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = group_name
    info.mtime = FIXED_MTIME
    if stat.S_ISDIR(status.st_mode):
        # Directory permissions created by mkdir are affected by the builder's umask. Package
        # directories are not executable payloads, so normalize them to the reviewed archive mode
        # instead of letting two otherwise identical hosts emit different bytes.
        info.mode = 0o755
        info.type = tarfile.DIRTYPE
    elif stat.S_ISREG(status.st_mode):
        info.mode = stat.S_IMODE(status.st_mode)
        info.type = tarfile.REGTYPE
        info.size = status.st_size
    else:
        raise ValueError(f"package source contains a special file: {path}")
    return info


def create(source: pathlib.Path, archive: pathlib.Path, group_name: str) -> None:
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError(f"package source is not a directory: {source}")
    archive.parent.mkdir(parents=True, exist_ok=True)
    paths = [source, *sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix())]
    with tempfile.NamedTemporaryFile(dir=archive.parent, delete=False) as temporary:
        temporary_path = pathlib.Path(temporary.name)
        try:
            with gzip.GzipFile(filename="", mode="wb", fileobj=temporary, compresslevel=9, mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as bundle:
                    for path in paths:
                        relative = pathlib.PurePosixPath(source.name)
                        if path != source:
                            relative /= pathlib.PurePosixPath(path.relative_to(source).as_posix())
                        info = archive_info(path, relative.as_posix(), group_name)
                        if info.isfile():
                            with path.open("rb") as stream:
                                bundle.addfile(info, stream)
                        else:
                            bundle.addfile(info)
            os.replace(temporary_path, archive)
            archive.chmod(0o644)
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise


def main() -> int:
    args = parser().parse_args()
    create(args.source, args.archive, args.group_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
