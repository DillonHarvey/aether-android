"""Build the original bounded native distribution directly at its final output."""

import argparse
import hashlib
import struct
from pathlib import Path


def number(value):
    return struct.pack("<Q", value)


def text(value):
    data = value.encode("ascii")
    return number(len(data)) + data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    build = args.build.resolve()
    output = args.output.resolve()
    if not output.is_relative_to(project / "out" / "distribution"):
        parser.error("Distribution outputs must be under out/distribution.")
    files = [("aether-setup.exe", build / "aether-setup.exe")]
    files += [
        (name, build / name)
        for name in ("aether.exe", "aether-shell.exe", "aether_runtime_setup.exe")
    ]
    files += [
        (f"runtime/{name}", build / "runtime" / name)
        for name in (
            "aether_worker.exe",
            "aether_graphics_worker.exe",
            "aether_icon_worker.exe",
        )
    ]
    library = build / "AetherShellIcons.dll"
    library_hash = hashlib.sha256(library.read_bytes()).hexdigest()
    files.append((f"shell-icons/{library_hash}/AetherShellIcons.dll", library))
    files += [
        (f"licenses/{path.name}", path)
        for path in sorted((project / "third_party" / "licenses").glob("*.txt"))
    ]
    payload = bytearray()
    # Contract 9: compact catalogue schema 5, retained icon capacity; stable launcher arguments/paths, package journal schemas 1-14,
    # existing Shell projections, LPAC worker policy, no app-data migration.
    manifest = bytearray(number(9) + number(len(files)))
    for name, source in files:
        data = source.read_bytes()
        if not 0 < len(data) <= 256 * 1024 * 1024:
            raise ValueError(f"Invalid distribution file size: {name}")
        manifest += (
            text(name)
            + number(len(payload))
            + number(len(data))
            + text(hashlib.sha256(data).hexdigest())
        )
        payload += data
    offset = len(payload)
    payload += manifest
    footer = b"AETHERBUNDLE2\0\0\0" + number(offset) + number(len(manifest))
    footer += hashlib.sha256(payload).hexdigest().encode("ascii")
    if len(footer) != 96 or len(payload) + len(footer) > 512 * 1024 * 1024:
        raise ValueError("Distribution exceeds its bound.")
    payload += footer
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    print(
        f"Aether distribution: {output} ({len(files)} files, {len(payload)} bytes; unsigned development build)"
    )


if __name__ == "__main__":
    main()
