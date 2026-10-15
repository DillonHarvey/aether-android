"""Original, bounded selection of the pinned ANGLE GN source inventories for Win32/D3D11.

This reads literal file lists, not executable GN/Python configuration. Platform additions
are explicit. Generated CMake/version headers are required build outputs under out/.
"""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import re

REVISION = "de6c60a3f64b0e300df6c75b6b554b9e41f4c0dc"
INVENTORIES = ("src/libGLESv2.gni", "src/compiler.gni", "src/libANGLE/renderer/d3d/d3d_backend.gni")


def select_sources(read):
    result = set()

    def group(file, name, base=""):
        text = read(file)
        pattern = rf"(?m)^\s*{re.escape(name)}\s*=\s*(?:\w+\s*\+\s*)?\[([^\]]*)\]"
        match = re.search(pattern, text)
        if not match:
            raise ValueError(f"Required upstream source group absent: {name}")
        entries = re.findall(r'"([^"\n]+)"', match[1])
        if not entries:
            raise ValueError(f"Empty upstream source group: {name}")
        for entry in entries:
            path = PurePosixPath(entry)
            if path.is_absolute() or any(c in entry for c in "$;\\:") or ".." in path.parts:
                raise ValueError(f"Unexpected non-literal source path: {entry}")
            if entry.endswith((".cpp", ".cc", ".c")):
                result.add(base+entry)

    for name in ("libangle_common_sources", "libangle_common_shader_state_sources", "xxhash_sources",
                 "libangle_image_util_sources", "libangle_gpu_info_util_sources",
                 "libangle_gpu_info_util_win_sources", "libangle_sources",
                 "libglesv2_entry_point_sources", "libglesv2_sources", "libegl_sources"):
        group(INVENTORIES[0], name)
    for name in ("angle_translator_sources", "angle_translator_essl_symbol_table_sources",
                 "angle_translator_hlsl_sources", "angle_preprocessor_sources"):
        group(INVENTORIES[1], name)
    for name in ("d3d_shared_sources", "d3d11_backend_sources"):
        group(INVENTORIES[2], name, "src/libANGLE/renderer/d3d/")
    result.update((
        "src/common/angle_version_info.cpp", "src/common/backtrace_utils_noop.cpp",
        "src/common/system_utils_win.cpp", "src/common/system_utils_win32.cpp",
        "src/common/gl_enum_utils.cpp", "src/common/gl_enum_utils_autogen.cpp",
        "src/image_util/AstcDecompressorNoOp.cpp",
        "src/libANGLE/capture/FrameCapture_mock.cpp", "src/libANGLE/capture/serialize_mock.cpp",
        "src/libANGLE/renderer/dxgi_format_map_autogen.cpp",
        "src/libANGLE/renderer/dxgi_support_table_autogen.cpp",
        "src/libANGLE/renderer/d3d/d3d11/win32/NativeWindow11Win32.cpp",
    ))
    return sorted(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vendor", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--build-identity", required=True)
    args = parser.parse_args()
    vendor, output = args.vendor.resolve(), args.output.resolve()
    project = Path(__file__).resolve().parent.parent
    if not output.is_relative_to(project / "out"):
        raise SystemExit("ANGLE generated build outputs must stay under this project's out directory")
    sources = select_sources(lambda name: (vendor/name).read_text(encoding="utf-8"))
    for source in sources:
        if not (vendor/source).is_file():
            raise SystemExit(f"Selected ANGLE source is absent: {source}")
    output.mkdir(parents=True, exist_ok=True)
    # Include all vendored bytes and the adapter in cache identity, not only .cpp files.
    digest = hashlib.sha256()
    for path in sorted(vendor.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(vendor).as_posix().encode()+b"\0")
            digest.update(path.read_bytes())
    digest.update(Path(__file__).read_bytes())
    digest.update((project/"cmake/Angle.cmake").read_bytes())
    digest.update(args.build_identity.encode("utf-8"))
    fingerprint = digest.hexdigest()

    def write(name, text):
        path = output/name
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")

    listing = "# Generated from pinned upstream GN lists by Aether's original adapter.\nset(AETHER_ANGLE_SOURCES\n"
    listing += "".join(f'    "{(vendor/source).as_posix()}"\n' for source in sources)+")\n"
    write("sources.cmake", listing)
    write("angle_commit.h", f'#define ANGLE_COMMIT_HASH "{REVISION[:12]}"\n#define ANGLE_COMMIT_HASH_SIZE 12\n'
                           '#define ANGLE_COMMIT_DATE "2026-10-08 10:40:47 +0000"\n'
                           '#define ANGLE_COMMIT_POSITION 0\n')
    write("ANGLEShaderProgramVersion.h", f'#define ANGLE_PROGRAM_VERSION "{fingerprint}"\n'
                                        f'#define ANGLE_PROGRAM_VERSION_HASH_SIZE {len(fingerprint)}\n')
    print(f"Selected {len(sources)} ANGLE Win32/D3D11 translation units")


if __name__ == "__main__":
    main()
