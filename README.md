# Aether

Aether is working towards running Android apps in normal Windows desktop windows, without an Android operating system or emulator. It translates supported Android code and connects app features to Windows.

Work in progress for Windows 11 on 64-bit Intel and AMD PCs.

## Implementation progress

<!-- aether:compatibility-progress:start -->

**910 / 3,589 implemented (25.36%)**

| Category | Total | Implemented | Progress |
| :--- | ---: | ---: | ---: |
| Packages & signing | 140 | 40 | 28.57% |
| ARM64 translation | 238 | 142 | 59.66% |
| Native libraries & POSIX | 457 | 119 | 26.04% |
| DEX & Java runtime | 601 | 257 | 42.76% |
| Java/native bridge (JNI) | 285 | 160 | 56.14% |
| Android framework | 231 | 18 | 7.79% |
| Screens & graphics | 862 | 54 | 6.26% |
| Files & networking | 198 | 14 | 7.07% |
| Media & devices | 236 | 0 | 0.00% |
| App engines | 128 | 0 | 0.00% |
| Security & permissions | 88 | 31 | 35.23% |
| Windows integration | 65 | 64 | 98.46% |
| Quality & reproducibility | 60 | 11 | 18.33% |
| **Total** | **3,589** | **910** | **25.36%** |

Counts describe source implementation within the recorded scope, not complete app compatibility.

<!-- aether:compatibility-progress:end -->

## Building on Windows

Use an x64 Visual Studio developer shell with CMake 3.25+, Ninja and Python 3.10+:

```powershell
cmake --preset windows-source-release
cmake --build --preset windows-source-release
```

The public repository contains source and build inputs; the private development test suite is not published. Debug and Release presets automatically disable tests when `tests/` is absent. The full development test suite cannot currently be reproduced from a public checkout.
