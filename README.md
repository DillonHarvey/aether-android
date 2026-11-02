# Aether

Aether is working towards running Android apps in normal Windows desktop windows, without an Android operating system or emulator. It translates supported Android code and connects app features to Windows.

Work in progress for Windows 11 on 64-bit Intel and AMD PCs.

## Implementation progress

<!-- aether:compatibility-progress:start -->

Catalogue last audited: 2026-11-02.

**933 / 3,589 implemented (26.00%)**

| Category | Total | Implemented | In progress | Not started | Progress |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Packages & signing | 140 | 40 | 45 | 55 | 28.57% |
| ARM64 translation | 238 | 142 | 87 | 9 | 59.66% |
| Native libraries & POSIX | 457 | 130 | 143 | 184 | 28.45% |
| DEX & Java runtime | 601 | 266 | 164 | 171 | 44.26% |
| Java/native bridge (JNI) | 285 | 160 | 88 | 37 | 56.14% |
| Android framework | 231 | 20 | 32 | 179 | 8.66% |
| Screens & graphics | 862 | 55 | 134 | 673 | 6.38% |
| Files & networking | 198 | 14 | 11 | 173 | 7.07% |
| Media & devices | 236 | 0 | 7 | 229 | 0.00% |
| App engines | 128 | 0 | 0 | 128 | 0.00% |
| Security & permissions | 88 | 31 | 29 | 28 | 35.23% |
| Windows integration | 65 | 64 | 1 | 0 | 98.46% |
| Quality & reproducibility | 60 | 11 | 42 | 7 | 18.33% |
| **Total** | **3,589** | **933** | **783** | **1,873** | **26.00%** |

**Completed areas:** Windows native install / shell / lifecycle (35/35).

Counts describe source implementation within the recorded scope, not complete app compatibility.

<!-- aether:compatibility-progress:end -->

## Building on Windows

Use an x64 Visual Studio developer shell with CMake 3.25+, Ninja and Python 3.10+:

```powershell
cmake --preset windows-source-release
cmake --build --preset windows-source-release
```

The public repository contains source and build inputs; the private development test suite is not published. Debug and Release presets automatically disable tests when `tests/` is absent. The full development test suite cannot currently be reproduced from a public checkout.
