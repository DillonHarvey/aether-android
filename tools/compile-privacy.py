"""Compile the authoritative privacy guide into a bounded, offline plain-text view.

This deliberately supports only the guide's small Markdown subset. Unsupported
formatting fails the build instead of silently losing a privacy statement.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def inline(value):
    if "![" in value:
        raise ValueError("Images are not supported in the privacy guide")
    value = re.sub(r"\[([^\[\]\n]+)\]\([^()\s]+\)", r"\1", value)
    value = re.sub(r"`([^`\n]+)`", r"\1", value)
    value = re.sub(r"\*\*([^*\n]+)\*\*", r"\1", value)
    if any(mark in value for mark in ("`", "*", "[", "]", "<", ">", "|")):
        raise ValueError("Unsupported inline privacy-guide formatting")
    return value


def render(source):
    if not source or len(source) > 65536:
        raise ValueError("Privacy source must contain 1..65536 UTF-8 bytes")
    text = source.decode("utf-8")
    if any((ord(c) < 32 and c not in "\r\n") or 127 <= ord(c) <= 159 for c in text):
        raise ValueError("Privacy source contains control characters")
    lines, output, index = text.splitlines(), [], 0
    while index < len(lines):
        line = lines[index].strip()
        if line.startswith("|"):
            rows = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                row = lines[index].strip()
                if not row.endswith("|"):
                    raise ValueError("Incomplete privacy table")
                rows.append([part.strip() for part in row[1:-1].split("|")])
                index += 1
            if (
                len(rows) < 3
                or len(rows[0]) < 2
                or any(len(row) != len(rows[0]) for row in rows)
                or not all(re.fullmatch(r"-{3,}", cell) for cell in rows[1])
                or any(not cell for row in rows for cell in row)
            ):
                raise ValueError("Unsupported privacy table")
            headings = [inline(cell) for cell in rows[0]]
            for row in rows[2:]:
                output.append(f"{headings[0]}: {inline(row[0])}")
                output.extend(
                    f"  {label}: {inline(cell)}"
                    for label, cell in zip(headings[1:], row[1:], strict=True)
                )
                output.append("")
            continue
        if line.startswith("#"):
            if not re.match(r"#{1,3} [^#]", line):
                raise ValueError("Unsupported privacy heading")
            line = line.lstrip("# ")
        output.append(inline(line))
        index += 1
    result = "\n".join(output).strip() + "\n"
    if len(result.replace("\n", "\r\n").encode("utf-16-le")) // 2 > 30000:
        raise ValueError("Rendered privacy guide exceeds the native text bound")
    return result


def compile_header(source):
    text = render(source)
    # JSON escaping is also valid for these validated UTF-8 C++ string literals.
    literals = "\n".join(
        json.dumps(line, ensure_ascii=False) for line in text.splitlines(True)
    )
    digest = hashlib.sha256(source).hexdigest()
    return (
        "// Generated from src/install/privacy_guide.txt; do not edit.\n"
        "#pragma once\n#include <string_view>\nnamespace aether::install::embedded {\n"
        f'inline constexpr std::string_view privacy_sha256 = "{digest}";\n'
        f"inline constexpr std::string_view privacy_text =\n{literals};\n"
        "} // namespace aether::install::embedded\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if (
        not output.is_relative_to(REPO / "out" / "build")
        or output.name != "privacy_content.hpp"
    ):
        parser.error(
            "Output must be privacy_content.hpp inside this project's out/build"
        )
    content = compile_header((REPO / "src/install/privacy_guide.txt").read_bytes())
    output.parent.mkdir(parents=True, exist_ok=True)
    if not output.exists() or output.read_text(encoding="utf-8") != content:
        output.write_text(content, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
