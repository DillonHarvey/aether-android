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
    # Contract 55: queued cache invalidation survives architectural CPU reset;
    # contract 54: preserve the nonfaulting register-prefetch SP boundary;
    # contract 53: actual managed widget selection policy, state20 and setter dirty witnesses;
    # contract 52: genuine collection selection callbacks and authoritative prepared selection projection;
    # contract 51: declared item-count/nonvirtual proof and immutable logical empty Grid cells;
    # contract 50: explicit guest collection metadata preparation, command16/state17 and Grid projection;
    # contract 49: acknowledged terminal activation custody on operations78/79;
    # contract 48: exact managed View activation facts and state16 completion custody;
    # contract 47: actual UIA Invoke completion on the original retained provider;
    # contract 46: explicit persisted clipboard consent and focused native plaintext broker;
    # contract 42: bounded soft-input request and acknowledged observation foundation (UI not connected);
    # contract 41: explicit per-document forwarding, startup schema 3 and owned file offers;
    # contract 40: explicit notification grant and verified installed host admission;
    # contract 39: command12 carries bounded native unchanged-prefix evidence for TextEdit targets;
    # contract 38: equal-byte Composition events and known-none targets without active composition;
    # contract 37: acknowledged actual TextEdit streaming through the app channel;
    # contract 36: synchronous observer and bounded schema1 observation record;
    # contract 35: actual callback mutations preserve retained-boundary conversion-target continuity;
    # contract 34: historical TextEdit delivery follows current semantics independently of geometry waits;
    # contract 33: state14 retains actual TextEdit payloads with their source buffer generation across swaps;
    # contract 32: one-shot host mutation delivery and current content overlays precede geometry publication;
    # contract 31: persistent bounded host range anchors advance on exact delivered publications;
    # contract 30: state13 carries bounded actual text mutation chains for range rebasing;
    # contract 29: command11 carries buffer/commit-bound selection and relative add/remove operations;
    # contract 28: state12 retains known TextEdit events before a later history gap;
    # contract 27: state11/command10 carries genuine native conversion targets/availability and ordered target events;
    # contract 26: state schema 10 carries bounded actual-operation TextEdit history and gap/buffer revisions;
    # contract 25: state/command schema 9 carries token-bound IME composition and actual input connections;
    # contract 24: state schema 8 edit event revisions and command schema 8 typed text reveal;
    # contract 23: command schema 7 carries exact-text-bound semantic selection;
    # contract 22: separate bounded read-only document provider and broker/stream operations;
    # contract 21: persisted owned link offers, raw native activation and dependency-aware cleanup;
    # contract 20: startup schema 2 checks explicit chooser membership against the original Intent;
    # contract 19: versioned immutable resolved-Intent startup and genuine Activity delivery;
    # contract 18: command schema 6 carries same-event Unicode key metadata and lock flags;
    # contract 17: Activity state schema 7 and command schema 5 add editable text/value actions;
    # contract 16: real scroll geometry/actions;
    # contract 15: current view descriptions;
    # contract 14: semantic eligibility/checked state;
    # contract 13: command schema 3 adds typed accessibility invocation;
    # contract 12 retains owned per-app toast activation projection and maintenance;
    # explicit installed playback consent/routing and per-app sessions;
    # committed historical icon aliases and matching cleanup;
    # catalogue schema 5, package schemas 1-14, stable paths and existing LPAC policy.
    manifest = bytearray(number(55) + number(len(files)))
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
