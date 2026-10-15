"""Verify a development bundle against its build and retained notice provenance, offline."""

import argparse
import datetime
import hashlib
import json
import os
import re
import stat
import struct
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
EXECUTABLES = (
    "aether-setup.exe",
    "aether.exe",
    "aether-shell.exe",
    "aether_runtime_setup.exe",
    "runtime/aether_worker.exe",
    "runtime/aether_graphics_worker.exe",
    "runtime/aether_icon_worker.exe",
)
MANIFESTS = (
    "third_party/dependencies.json",
    "third_party/dynarmic-dependencies.json",
    "third_party/angle-dependencies.json",
)
NOTICE_MANIFEST = "third_party/toolchain-notices.json"
NDK_NOTICES = {"android-ndk-r30-NOTICE.txt", "android-ndk-r30-toolchain-NOTICE.txt"}
MAX_IMAGE = 512 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_METADATA = 8 * 1024 * 1024
MAX_NOTICE = 4 * 1024 * 1024
MAGIC = b"AETHERBUNDLE2\0\0\0"


class VerificationError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = "AETHER_DISTRIBUTION_" + code


def require(condition, code, message):
    if not condition:
        raise VerificationError(code, message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def regular_file(info):
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and not getattr(info, "st_file_attributes", 0) & 0x400
    )


def read_bounded(path, limit):
    """Read one normal final file once; detect replacement/change, without retries."""
    before = path.lstat()
    require(regular_file(before), "FILE", f"Expected a normal single-link file: {path}")
    require(
        0 < before.st_size <= limit,
        "LIMIT",
        f"File exceeds its size bound or is empty: {path}",
    )
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        require(
            regular_file(opened), "FILE", f"Opened file has an unsupported type: {path}"
        )

        def identity(s):
            return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)

        require(
            identity(before) == identity(opened),
            "CHANGED",
            f"File changed before reading: {path}",
        )
        data = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    require(
        len(data) == before.st_size
        and identity(before) == identity(after) == identity(path.lstat()),
        "CHANGED",
        f"File changed during reading: {path}",
    )
    return data


def decode_manifest(data, name):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(
                key not in result, "PROVENANCE", f"Duplicate JSON key in {name}: {key}"
            )
            result[key] = value
        return result

    require(len(data) <= MAX_METADATA, "LIMIT", f"Metadata exceeds its bound: {name}")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise VerificationError(
            "PROVENANCE", f"Unreadable JSON metadata: {name}"
        ) from error
    require(
        isinstance(value, dict)
        and type(value.get("schemaVersion")) is int
        and value["schemaVersion"] == 1,
        "PROVENANCE",
        f"Unsupported metadata schema: {name}",
    )
    return value


def notice_inventory(documents, fixture, available):
    """Expected notice names come from provenance, independently of the packager's glob."""
    notices = {}
    folded = set()

    def add(path, sha256, manifest, component):
        require(
            isinstance(path, str) and path.startswith("third_party/licenses/"),
            "PROVENANCE",
            "Notice path must be under third_party/licenses",
        )
        name = path.removeprefix("third_party/licenses/")
        require(
            len(name) <= 151
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*[.]txt", name)
            and ".." not in name,
            "PROVENANCE",
            f"Unsupported notice filename: {name}",
        )
        require(
            valid_digest(sha256),
            "PROVENANCE",
            f"Invalid recorded notice digest: {name}",
        )
        require(
            name.casefold() not in folded,
            "PROVENANCE",
            f"Duplicate notice identity: {name}",
        )
        folded.add(name.casefold())
        notices[name] = {
            "source": path,
            "sha256": sha256,
            "manifest": manifest,
            "component": component,
        }

    for name in MANIFESTS:
        document = documents[name]
        require(
            isinstance(document.get("dependencies"), list),
            "PROVENANCE",
            f"Missing dependencies: {name}",
        )
        for dependency in document["dependencies"]:
            require(
                isinstance(dependency, dict)
                and isinstance(dependency.get("name"), str)
                and isinstance(dependency.get("files"), list),
                "PROVENANCE",
                f"Invalid dependency: {name}",
            )
            for item in dependency["files"]:
                require(
                    isinstance(item, dict) and isinstance(item.get("path"), str),
                    "PROVENANCE",
                    f"Invalid file record: {name}",
                )
                if item["path"].startswith("third_party/licenses/"):
                    add(item["path"], item.get("sha256"), name, dependency["name"])
    ndk = fixture.get("noticeHashes")
    require(
        isinstance(ndk, dict) and set(ndk) == NDK_NOTICES,
        "PROVENANCE",
        "Toolchain provenance must bind both retained NDK r30 notices",
    )
    for name, sha256 in ndk.items():
        add(
            "third_party/licenses/" + name,
            sha256,
            NOTICE_MANIFEST,
            "NDK r30 fixture support",
        )
    require(
        set(notices) == set(available),
        "NOTICE_INVENTORY",
        "Notice directory differs from provenance; missing="
        + repr(sorted(set(notices) - set(available)))
        + "; unrecorded="
        + repr(sorted(set(available) - set(notices))),
    )
    require(
        9 <= len(notices) + len(EXECUTABLES) + 1 <= 96,
        "LIMIT",
        "Payload inventory exceeds the bundle bound",
    )
    return notices


def inspect_bundle(data, expected):
    """Independent bounded decoder; never execute, extract, repair or import the packager."""
    require(
        96 <= len(data) <= MAX_IMAGE,
        "LIMIT",
        "Bundle size is outside the supported bound",
    )
    view = memoryview(data)
    footer = len(data) - 96
    require(
        view[footer : footer + 16] == MAGIC,
        "FORMAT",
        "Expected a version-2 Aether bundle footer",
    )
    manifest_at, manifest_size = struct.unpack_from("<QQ", view, footer + 16)
    require(
        manifest_size <= 65536
        and manifest_at <= footer
        and manifest_at + manifest_size == footer,
        "FORMAT",
        "Manifest is outside its bounded region",
    )
    require(
        digest(view[:footer]).encode("ascii") == view[footer + 32 :],
        "DIGEST",
        "Whole-image manifest digest does not match",
    )
    cursor = manifest_at

    def number():
        nonlocal cursor
        require(cursor + 8 <= footer, "FORMAT", "Truncated manifest integer")
        result = struct.unpack_from("<Q", view, cursor)[0]
        cursor += 8
        return result

    def text(bound):
        nonlocal cursor
        length = number()
        require(
            length <= bound and cursor + length <= footer,
            "FORMAT",
            "Invalid manifest string size",
        )
        try:
            result = bytes(view[cursor : cursor + length]).decode("ascii")
        except UnicodeError as error:
            raise VerificationError(
                "FORMAT", "Manifest strings must be ASCII"
            ) from error
        cursor += length
        return result

    require(number() == 7, "CONTRACT", "Expected current compatibility contract 7")
    count = number()
    require(7 <= count <= 96, "LIMIT", "Invalid manifest file count")
    files = {}
    end = 0
    for _ in range(count):
        name = text(160)
        offset, size, sha256 = number(), number(), text(64)
        require(
            name in expected and name not in files,
            "LAYOUT",
            f"Unexpected or duplicate payload: {name}",
        )
        require(
            offset == end
            and 0 < size <= MAX_FILE
            and offset <= manifest_at
            and size <= manifest_at - offset
            and valid_digest(sha256),
            "FORMAT",
            f"Invalid payload span/digest: {name}",
        )
        end = offset + size
        require(
            digest(view[offset:end]) == sha256,
            "DIGEST",
            f"Payload digest does not match: {name}",
        )
        source = expected[name]
        require(
            size == source["bytes"] and sha256 == source["sha256"],
            "SOURCE_MISMATCH",
            f"Payload differs from the reviewed source/current build: {name}",
        )
        files[name] = dict(source, offset=offset)
    require(
        cursor == footer and end == manifest_at,
        "FORMAT",
        "Unclaimed manifest or payload bytes",
    )
    require(
        set(files) == set(expected) and next(iter(files)) == "aether-setup.exe",
        "LAYOUT",
        "Bundle is missing required files or its leading setup image",
    )
    return files


def verify(project, build, bundle, report):
    source_hashes = report["sourceHashes"]

    def source(name, bound=MAX_METADATA):
        data = read_bounded(project / name, bound)
        source_hashes[name] = digest(data)
        return data

    for name in (
        "tools/verify-distribution.py",
        "tools/package-runtime.py",
        "CMakeLists.txt",
        "src/install/runtime_bundle.cpp",
        "src/install/runtime.cpp",
    ):
        source(name)
    documents = {name: decode_manifest(source(name), name) for name in MANIFESTS}
    fixture = decode_manifest(source(NOTICE_MANIFEST), NOTICE_MANIFEST)
    notices = notice_inventory(
        documents,
        fixture,
        [p.name for p in (project / "third_party/licenses").glob("*.txt")],
    )
    expected = {}
    for name in EXECUTABLES:
        path = build / name
        data = read_bounded(path, MAX_FILE)
        expected[name] = {
            "source": str(path),
            "role": "executable",
            "bytes": len(data),
            "sha256": digest(data),
        }
    library = build / "AetherShellIcons.dll"
    data = read_bounded(library, MAX_FILE)
    library_hash = digest(data)
    expected[f"shell-icons/{library_hash}/AetherShellIcons.dll"] = {
        "source": str(library),
        "role": "shell-library",
        "bytes": len(data),
        "sha256": library_hash,
    }
    for name, record in sorted(notices.items()):
        data = source(record["source"], MAX_NOTICE)
        require(
            digest(data) == record["sha256"],
            "PROVENANCE",
            f"Retained notice differs from its recorded hash: {name}",
        )
        expected["licenses/" + name] = dict(record, bytes=len(data), role="notice")
    data = read_bounded(bundle, MAX_IMAGE)
    report.update(bundleBytes=len(data), bundleSha256=digest(data))
    report["files"] = inspect_bundle(data, expected)
    report.update(
        fileCount=len(expected),
        executableCount=len(EXECUTABLES),
        noticeCount=len(notices),
        shellLibraryCount=1,
        compatibilityContract=7,
        wholeImageDigestMatches=True,
        currentBuildMatches=True,
        retainedNoticeProvenanceMatches=True,
    )


def evidence_path(value, build):
    if value is None:
        return None
    value = value.absolute()
    require(
        value.parent.resolve() == build
        and re.fullmatch(r"distribution-[A-Za-z0-9_.-]+[.]json", value.name),
        "OUTPUT",
        "Evidence must be a distribution-*.json file directly in the selected build directory",
    )
    require(not value.is_symlink(), "OUTPUT", "Evidence cannot be a symbolic link")
    if value.exists():
        require(
            regular_file(value.lstat()),
            "OUTPUT",
            "Evidence must be a normal single-link report file",
        )
    return value


def write_report(path, report):
    if path is not None:
        path.write_text(
            json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument(
        "--evidence",
        type=Path,
        help="Explicit final distribution-*.json result in the build directory",
    )
    parser.add_argument(
        "--json", action="store_true", help="Print the complete machine-readable result"
    )
    args = parser.parse_args(arguments)
    report = {
        "schemaVersion": 1,
        "operation": "verify-development-distribution",
        "passed": False,
        "createdUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sourceHashes": {},
        "publisherAuthenticated": False,
        "publicReleaseCleared": False,
        "licenceClearanceEstablished": False,
        "runtimeUpgradeCompatibilityAssessed": False,
        "guestExecution": False,
        "uploaded": False,
        "limitations": [
            "Current source/build byte identity only; no publisher or legal clearance",
            "Not a full vendor integrity check, symbol SBOM or executable safety analysis",
            "No installed-runtime layout, Windows UI or clean-machine acceptance",
        ],
    }
    output = None
    output_started = False
    try:
        build = args.build.resolve()
        require(
            build.is_dir()
            and build != PROJECT / "out/build"
            and build.is_relative_to(PROJECT / "out/build"),
            "INPUT",
            "Build must be an existing final directory under this project's out/build",
        )
        output = evidence_path(args.evidence, build)
        require(
            output is None or output.resolve() != args.bundle.resolve(),
            "OUTPUT",
            "Evidence cannot replace the input bundle",
        )
        report.update(
            build=str(build),
            bundle=str(args.bundle.absolute()),
            evidence=str(output) if output else None,
        )
        # Invalidate a prior pass before input reads. All writes go directly to the selected final report.
        write_report(output, report)
        output_started = True
        verify(PROJECT, build, args.bundle.absolute(), report)
        report["passed"] = True
    except VerificationError as error:
        report.update(code=error.code, message=str(error))
    except OSError as error:
        report.update(code="AETHER_DISTRIBUTION_IO", message=str(error))
    except (KeyError, TypeError, ValueError) as error:
        report.update(
            code="AETHER_DISTRIBUTION_INTERNAL",
            message=f"{type(error).__name__}: {error}",
        )
    try:
        if output_started:
            write_report(output, report)
    except OSError as error:
        report.update(
            passed=False, code="AETHER_DISTRIBUTION_OUTPUT", message=str(error)
        )
    if args.json:
        print(json.dumps(report, ensure_ascii=True))
    elif report["passed"]:
        print(
            f"Distribution verified: {report['fileCount']} files ({report['executableCount']} executables, "
            f"{report['noticeCount']} notices); SHA-256 {report['bundleSha256']}. Development integrity only."
        )
    else:
        print(report["code"] + ": " + report["message"], file=sys.stderr)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
