<p align="center">
  <img src="docs/assets/aether-banner.svg" alt="Aether — Android apps, at home on Windows. An illustration of the project vision." width="1200" />
</p>

# Aether

**Bringing Android apps to your Windows desktop.**

Aether is a project working towards a simple idea: install an Android app on your PC, open it in a normal Windows window, and manage it through Windows.

This page explains the project in everyday language. No programming knowledge needed.

**Project snapshot · 27 October 2026 · Windows 11 on Intel or AMD PCs (64-bit)**

[The idea](#the-idea) · [Where we are](#where-we-are) · [What works](#what-works-today) · [Progress counts](#progress-counts) · [Trying Aether](#can-i-try-it)

> **Currently in development.** Eight development phases are complete. Phase 8, Windows integration and wider app support, is in progress. Aether can run its own test apps, but everyday Android app compatibility is still limited.

**Security scope - 24 October 2026:** Current work is limited to basic safeguards. Existing protections stay in place; advanced hardening and security testing are deferred.

## The idea

Android apps expect features that Windows does not provide in the same way. Aether acts as a translator: it runs supported Android app code and connects supported app features to Windows.

Windows does the underlying work, without needing to start an Android operating system or a virtual machine. Aether also translates supported ARM64 code, commonly used by Android phones, for Intel and AMD PCs.

### The experience we are building

1. **Install Aether once.** One shared installation supports your compatible Android apps.
2. **Open an Android app file.** An **APK** is an Android installation file. Open it through File Explorer, review the app details and permissions, then approve installation.
3. **Launch it like a Windows app.** Find it in Start or Search and use it in its own window, with its own name, icon and private app data.
4. **Manage it through Windows.** Update compatible apps while keeping their data, and remove individual apps through Windows Settings.

You can choose Aether to open APK files when you double-click them. Opening an APK brings up installation review; it does not silently run the app.

**This is the intended finished experience.** The installation and launch system exists, and package icons have been checked in six actual Explorer views. Checks of Start, Search, taskbar pins and Windows Settings remain unfinished. The plan uses Windows' familiar controls, with small Aether dialogs when needed.

## Where we are

| At a glance | Current position |
| :--- | :--- |
| **Development phases** | **8 complete · 1 in progress**, numbered 0–8 |
| **Current focus** | **Phase 8:** Windows installation, launch, updates and wider compatibility |
| **Distinct working test apps** | **3 / 3 required scenarios recorded:** HelloAether, PlainAether and Pocket Tally |
| **Owner-supplied app files** | **9 inspected · 9 with Explorer icons · 6 installed · 0 verified functional apps** |
| **Compatibility checklist** | **3,589 planning entries** in **13 categories / 43 areas** |
| **Catalogue implementation** | **894 of 3,589 implemented (24.91%)** |
| **Remaining catalogue work** | **2,695 entries: 749 partial and 1,946 not started** |
| **Public release** | Still in development; release requirements remain open |

Development phases vary greatly in size. Completing eight phases does not mean the finished product is almost ready, or that a similar share of Android apps will work.

The local progress and app compatibility records contain the evidence behind this snapshot. The three-app milestone is one part of Phase 8; it does not complete the phase.

## What works today

These are **demonstrated capabilities within a limited scope**, updated from local engineering records through 27 October 2026. They describe implementation progress separately from the checklist's review percentages below.

### 📦 App files, installation and updates

| Capability | Recorded working behaviour | Remaining scope |
| :--- | :--- | :--- |
| **Package inspection** | Reads supported APKs and XAPK sets; reports app identity, launch screen, permissions, code files, native libraries, resources and signing. All nine supplied files have full inspection checkpoints. | Passing inspection does not establish a successful app launch. |
| **Split packages** | Verifies supported XAPK member sets and provides bounded installation, resource/asset composition and app-code delivery through the installed path. | General device/configuration selection, APKS installation and expansion-file support remain unfinished. |
| **Signature checks** | Verifies supported APK v2, v3 and v3.1 companion signatures, including bounded DSA-SHA256 support; keeps and rechecks signing identities. | Unsupported signing is reported explicitly. Verification does not authenticate the publisher or prove that an app is safe. |
| **App installation and updates** | Reviews the package checksum and permission choices; keeps app data separate; updates eligible apps while preserving identity, data and grants; repairs tested interrupted operations. | Updates that change signing keys and broader failure recovery remain unfinished. |
| **Shared Aether installation** | Provides a native development installer/uninstaller and compatible upgrades at the existing location, with checks for apps that still depend on Aether. | Fresh-PC acceptance, incompatible migrations and release signing remain open. |

### ⚙️ Android code, screens and saved data

| Capability | Recorded working behaviour | Remaining scope |
| :--- | :--- | :--- |
| **Three distinct apps** | HelloAether, PlainAether and Pocket Tally complete their defined scenarios through the installed, isolated Windows runtime. | These are original test apps; no supplied third-party app has a verified functional workflow. |
| **Managed and ARM64 code** | Executes supported Android bytecode, translates supported ARM64 native code and passes calls both ways through JNI, the bridge between them. | The managed runtime, Java libraries, native loader and Android APIs each support a subset. |
| **Multiple code files** | Links supported multi-DEX packages and loads needed code files on demand. Focused fixtures exercise cross-file calls and default interface methods. | File, memory and instruction limits apply; admitting a package does not validate every code path. |
| **More language and resource behaviour** | Supports bounded switch instructions, array cloning, generated class names, compiled resource names, structured resource values and neutral density/API selection. Errors can identify the failing DEX table, record and byte offset. | Full Android themes, locale/device configuration and many language/API features remain unfinished. |
| **Interactive windows and persistence** | Shows basic app screens in resizable Windows windows with mouse/keyboard input and app lifecycle events. Pocket Tally saves a count through its own ARM64 library and reloads it after reopening. | Saving needs the app's private-file permission; the counter's save is not crash-atomic. |

### Recent source progress - 27 October 2026

Current source adds Android launch information that app code can read and update, preserves the selected app component through startup and screen recreation, and implements seven more individual framework methods in the catalogue.

Supported link-routing conditions can now be decoded and matched to eligible app screens. An internal launch path carries the supplied request into a genuine Android Intent, with the worker checking the selected component against the held APK before app initialization. Unknown policy/resources, competing screens and unsupported task or file-access flags are refused. Selected Release/Debug library builds and worker compilation are recorded as passing; running-app behavior remains unverified.

Windows request forwarding and its permission choices, resource-backed routing, Android preference selection, broader task delivery and notification actions remain unfinished. These partial routing additions do not increase the implemented count beyond **894 / 3,589**.

The current goal retains **all 3,589 catalogue entries**. Within that goal, the historical five-category subset covers 1,277 requirements across Windows integration, ARM64 translation, JNI, DEX/Java and security: **638 are source-implemented (49.96%); 639 remain.** All five remain incomplete. Windows integration has the highest implemented share at **53/65 (81.54%)**, with **12 entries remaining**. Recent source additions include ARM64 scheduling/cache operations and a bounded scalar atomic-instruction fallback; JNI primitive-array copies, string regions, ordinary constructors and nonvirtual calls; and Java string comparison, literal replacement and weak interning. Each retains explicit limits and unsupported cases. Recent source work also adds array copying, backed JNI local-reference capacity, precise cache-operation failures and a bounded vertical scrolling layout with Windows accessibility actions. These changes have compiled; running-app behavior remains unverified.

Windows source work adds a bounded UI Automation view tree with supported Invoke/focus actions, legacy icon-path repair, graceful-close coordination before removal, interrupted-upgrade recovery and per-app native sound playback with explicit default-off consent. General editable/scrolling accessibility, Android media APIs and notification activation/consent remain unfinished. **Installed notifications stay disabled.**

The retained 26 October milestone records successful selected production-library compilation in **Release and Debug**, after documented compile issues were corrected. Runtime, APK, Windows UI, Android-oracle and clean-profile acceptance did not run. Under the current owner direction, project tests, self-tests, probes and test-purpose APK launches remain **deferred, not passed**. This source work has not upgraded the installed runtime or established a functional third-party app workflow.

### 🪟 Windows integration and package artwork

| Capability | Recorded working behaviour | Remaining scope |
| :--- | :--- | :--- |
| **Explorer and Open With** | Offers an optional installation action, preserves the user's file-handler choice and opens installation review before execution. | Broader default-handler and clean-machine checks remain open. |
| **Individual app identities** | Creates Start shortcuts and Installed apps registrations; gives each app its own window identity and stable relaunch command. Supports per-app removal and registration repair. | Actual Start/Search/Settings screens, taskbar grouping and pinned relaunch still need acceptance checks. |
| **Real package icons** | Shows all nine supplied files' distinct icons in Explorer's Details, List, Small, Medium, Large and Extra large views. Uses bounded PNG/WebP/drawable handling and an isolated metadata worker. | Multiple display scales and fresh-PC acceptance remain open. An icon is not a working-app result. |
| **Icons across app updates** | Keeps registered icon paths stable and updates supported installed artwork with the app version. | Cached icons on actual taskbar pins remain unverified. |

### 🔒 Isolation, permissions and troubleshooting

| Capability | Recorded working behaviour | Remaining scope |
| :--- | :--- | :--- |
| **Isolated execution** | Uses restricted Windows workers, app-specific storage, package-integrity checks and permission-checked host services. Failed isolation refuses execution. | This is the recorded, scoped security model; broader Android services still need implementation. |
| **Per-app settings** | Native dialogs and CLI controls expose basic time, private-file and separately consented wall-clock permissions. Automatic one-second reads recover after failures and preserve unsaved choices, focus and selection. | Current source adds separately consented, default-off sound playback. Network, camera, microphone and other unsupported grants remain unavailable. |
| **Diagnostics and reports** | Provides read-only app checks and explicit JSON export, plus optional build details and bounded audit summaries with a preview before saving. | Reports do not certify compatibility or diagnose every crash; nothing is uploaded automatically. |
| **Offline privacy information** | Includes the privacy and permissions guide in setup, app controls and the CLI. Builds verify the packaged dependency notices and payload identities. | Public licensing, publisher authentication and release review remain open. |

### 🎨 Graphics and sound foundations

Separate native test programs demonstrate **EGL/OpenGL ES graphics through ANGLE and Direct3D 11**, including window input and resize, and **AAudio output through Windows WASAPI**, with permission and cleanup checks. Audio tests use a muted session. The ordinary test-app screens use a separate Windows drawing path; current source also routes supported installed native synchronous PCM16 AAudio through the broker to app-attributed WASAPI sessions with separate playback consent. Playback and Windows mixer acceptance for that addition remain deferred. General Android graphics, Java media, video and game-engine compatibility remain unfinished.

The public implementation is in [package handling](src/apk/), [managed execution](src/dex/), [native translation](src/a64/), [installation](src/install/), [Windows integration](src/shell/) and [isolation](src/security/). Detailed test evidence and engineering decisions are retained locally. This README update reuses those records; it does not claim new runtime test passes.

## Progress counts

The **27 October 2026 authoritative CSV snapshot** records **894 implemented (24.91%)**, **749 in progress** and **1,946 not started** among **3,589 entries**, with none unassessed or blocked. Category and area counts below are recalculated directly from the current CSV.

| Implementation status | Entries | Share |
| :--- | ---: | ---: |
| Implemented | 894 | 24.91% |
| In progress | 749 | 20.87% |
| Not started | 1,946 | 54.22% |
| **Total** | **3,589** | **100.00%** |

There are **2,695 entries still incomplete**. New source work under review is not counted as implemented until its catalogue disposition is updated.

These are recorded **source implementation dispositions**, checked against the CSV on 27 October 2026. They do not establish acceptance-test passes. Detailed source references, review notes and independent test/verification fields remain in the local catalogue; this README update does not reassess every implementation or change those records.

The tables count **implemented catalogue requirements**. Partial work and unsupported requirements do not increase the percentage. Implementation and complete test verification remain separate, and successful real-app workflows are reported separately below.

<!-- aether:compatibility-progress:start -->

**894 / 3,589 entries implemented (24.91%)**

Implementation means the catalogue requirement exists within its recorded scope. It does not mean full acceptance testing or app compatibility.

The denominator retains overlapping parents and refinements; this is the implemented share of this catalogue, not a percentage of Android.

| Category | Entries | Implemented | % |
| :--- | ---: | ---: | ---: |
| Packages & signing | 140 | 40 | 28.57% |
| ARM64 translation | 238 | 137 | 57.56% |
| Native libraries & POSIX | 457 | 119 | 26.04% |
| DEX & Java runtime | 601 | 257 | 42.76% |
| Java/native bridge (JNI) | 285 | 160 | 56.14% |
| Android framework | 231 | 18 | 7.79% |
| Screens & graphics | 862 | 54 | 6.26% |
| Files & networking | 198 | 14 | 7.07% |
| Media & devices | 236 | 0 | 0.00% |
| App engines | 128 | 0 | 0.00% |
| Security & permissions | 88 | 31 | 35.23% |
| Windows integration | 65 | 53 | 81.54% |
| Quality & reproducibility | 60 | 11 | 18.33% |
| **Total** | **3,589** | **894** | **24.91%** |

Only **Implemented** entries count. Partial, not-started, blocked and unassessed entries contribute zero.

<details>
<summary>All 43 areas</summary>

| Area | Entries | Implemented | % |
| :--- | ---: | ---: | ---: |
| APK, signing and distribution | 46 | 22 | 47.83% |
| APK and manifest detailed formats | 94 | 18 | 19.15% |
| ARM64 guest translation and ABI | 27 | 10 | 37.04% |
| AArch64 instruction conformance | 211 | 127 | 60.19% |
| Android native ELF loading and dynamic linker | 30 | 1 | 3.33% |
| ELF and linker detailed conformance | 71 | 18 | 25.35% |
| Bionic libc and POSIX compatibility | 42 | 9 | 21.43% |
| Bionic and POSIX exported calls | 314 | 91 | 28.98% |
| DEX parser, linking and runtime support | 45 | 12 | 26.67% |
| DEX opcodes | 224 | 162 | 72.32% |
| DEX runtime detailed contracts | 67 | 28 | 41.79% |
| ART-compatible managed semantics | 27 | 3 | 11.11% |
| ART semantic edge cases | 44 | 5 | 11.36% |
| Java/Kotlin standard runtime libraries | 33 | 0 | 0.00% |
| Java core library individual methods | 161 | 47 | 29.19% |
| JNI API | 234 | 124 | 52.99% |
| JNI semantic edge cases | 51 | 36 | 70.59% |
| Android framework and app lifecycle | 71 | 0 | 0.00% |
| Android framework individual methods | 160 | 18 | 11.25% |
| Android Views and resources | 63 | 0 | 0.00% |
| Android graphics, UI and resources detailed | 105 | 1 | 0.95% |
| EGL, GLES, Vulkan and shader runtime | 48 | 2 | 4.17% |
| EGL core commands | 44 | 6 | 13.64% |
| OpenGL ES core commands | 358 | 28 | 7.82% |
| GLSL ES shader conformance | 131 | 16 | 12.21% |
| Graphics formats and textures | 64 | 1 | 1.56% |
| Vulkan early research surface | 49 | 0 | 0.00% |
| Android storage, persistence and data | 40 | 3 | 7.50% |
| SQLite, files and persistence detailed | 71 | 10 | 14.08% |
| Networking and TLS | 27 | 1 | 3.70% |
| Networking and crypto detailed | 60 | 0 | 0.00% |
| Audio, video, codecs and imaging | 28 | 0 | 0.00% |
| Audio/video/media detailed | 98 | 0 | 0.00% |
| Host devices and Android hardware APIs | 30 | 0 | 0.00% |
| Device and system-services detailed | 80 | 0 | 0.00% |
| App engines and third-party ecosystem | 31 | 0 | 0.00% |
| Embedded application engines detailed | 97 | 0 | 0.00% |
| Windows isolation and Android permission security | 43 | 15 | 34.88% |
| Permissions and defensive compatibility | 45 | 16 | 35.56% |
| Windows native install / shell / lifecycle | 35 | 30 | 85.71% |
| Windows product integration detailed | 30 | 23 | 76.67% |
| Reproducibility and test coverage | 30 | 5 | 16.67% |
| QA and progress evidence systems | 30 | 6 | 20.00% |

</details>

### Where the entries came from

Entries are grouped by the technical reference recorded in each catalogue row. These are requirement sources, not claims that their implementation code was copied.

| Specification or documentation source | Entries |
| :--- | ---: |
| [Android Developers: API, NDK and app guides](https://developer.android.com/) | 1,697 |
| [Android Open Source Project: DEX, bytecode, ART and CTS](https://source.android.com/) | 470 |
| [Khronos: OpenGL ES, EGL and Vulkan specifications / headers](https://registry.khronos.org/) | 687 |
| [Arm: AArch64 instruction reference and ELF ABI](https://support.arm.com/documentation/ddi0602/2026-06) | 282 |
| [Oracle: JNI function specification](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html) | 234 |
| [Microsoft Learn: Windows shell, AppContainer and UI Automation](https://learn.microsoft.com/en-us/windows/win32/) | 65 |
| Aether project requirements: Windows integration, security and quality goals | 154 |
| **Total planning entries** | **3,589** |

Each entry is counted once by its recorded source. Project-specific requirements remain attributed to Aether's plan; overlapping requirements remain in the catalogue.

<!-- aether:compatibility-progress:end -->

**How this updates:** the catalogue tool recalculates every category and area from the authoritative CSV when synchronized. This README snapshot was read directly from the CSV on 27 October 2026; generated summaries can lag behind it. GitHub shows the latest committed README; the CSV, Excel view and detailed source evidence remain local.

**How to read the percentages:** Implemented entries divided by all entries in that category. Partial work contributes zero. All entries now have an implementation disposition, while test verification and real-app outcomes remain separate. Overlapping broad requirements and refinements mean this is a catalogue ratio, not the percentage of Android supported.

## Which apps have been tried?

| App | What the record shows |
| :--- | :--- |
| **HelloAether** — our own test app | Opens a Windows window. Its button runs Android app code and translated ARM64 code, then displays **ARM64 result: 42**. |
| **PlainAether** — our second test app | Runs a separate, simpler Android app through the installed-app system. Its versions are also used to check updates and preserved app data. |
| **Pocket Tally** — our third test app | Counts, saves through its own ARM64 library and reloads the saved value after reopening. Recorded scenarios include permission denial/revocation, damaged records and another app remaining usable after removal. |

That is **three distinct working test apps**, with bounded installed-path scenarios recorded in Debug and Release. Signed versions, multi-DEX probes and modified copies do not increase that count.

### Owner-supplied apps

| Checkpoint for the nine supplied APK/XAPK files | Recorded result |
| :--- | :--- |
| Full metadata-inspection checkpoint | **9 / 9** |
| Distinct icons visible in six Explorer views | **9 / 9** |
| Installed owner apps in the 23 October observed store record | **6 / 9** |
| Verified functional app workflows | **0 / 9** |

The frozen intake contains **4 APKs and 5 XAPK sets**. The 23 October observed store record lists **Candy Crush, Galaxy Defense, Genshin cloud game, Subway, TikTok and the file labelled "The Sims 4"** (package `com.am.obby.runner.world.game`) installed. **Alchemia has data retained after removal**; Facebook and Ni no Kuni are absent from that observed store. Installation history and functional verification remain separate.

TikTok's latest retained 24 October isolated startup record still exits with failure; no usable Activity, video playback or functional workflow is verified. It reached the existing worker memory limit; the exact failed allocation remains unproved. Later parser error-preservation work compiled, but its tests, deployment and owner retry remain deferred. Alchemia's original APK passes the recorded bounded DSA-SHA256 signature check, without a new installation or launch. No owner app was installed, launched or retried for this README update.

Experimental installation supports eligible standalone APKs and a bounded XAPK split path, with supported multi-DEX loading, explicit consent and Windows isolation. Many apps still encounter missing Android APIs, native-library or memory limits. A package inspection, installation preview or icon does not establish successful execution.

No supplied third-party app is currently claimed compatible. Google Play Services, protected streaming, banking apps, anti-cheat games and universal Android support are not promised. The local per-app tracker preserves each input's identity, results and remaining requirements.

## Can I try it?

**Aether is currently a development project.** A Windows installer is built by the project, but it is an unsigned development build and the complete public-release experience is still unfinished.

The current target is **Windows 11 on a 64-bit Intel or AMD PC**. Windows on ARM, macOS and Linux are outside the current target.

To follow the project, start with the current capabilities and progress counts above. To build the published source, use the instructions below. Building currently requires developer tools.

### A few useful words

| Word | Plain-English meaning |
| :--- | :--- |
| **APK** | A file used to distribute and install an Android app. |
| **Runtime** | The shared Aether software that runs compatible apps. |
| **Compatibility** | How well an app's required features behave through Aether. |
| **App signature** | A digital seal used to check that an app file has not changed. It does not prove an app is safe. |
| **Sandbox / isolation** | Restrictions on an app's access to the PC and other apps' data. |
| **Test app / fixture** | A small app made specifically to check whether something works. |

## Build from this repository

The GitHub repository contains project source, required third-party source and
licence notices, build and publishing scripts, and this README with its banner.
Development tests, fixtures, engineering documents, owner APKs and generated
binaries stay in the local development workspace.

On Windows 11 x64, install Visual Studio 2022 Build Tools with the Desktop
development with C++ workload (including its CMake/Ninja tools), the Windows SDK,
Git and Python 3.12. In PowerShell at the project root, run:

```powershell
./tools/build.ps1 -Preset windows-source-release
```

This builds the runtime and unsigned development installer without the local test
suite. The installer is written to
`out/distribution/windows-source-release/AetherSetup.exe`. No Android emulator or
Android system image is required. The privacy text shown inside the application
is a product resource at `src/install/privacy_guide.txt`; complete third-party
notices are in `third_party/licenses/`.

The full development workspace retains its existing Debug/Release test presets
and CI checks. Their test sources are intentionally excluded from this repository.
A successful source build does not establish app compatibility or release readiness.

## Weekly source uploads

The owner's development PC is configured to publish saved project files every
**Friday at 6:00 pm Sydney time**. The Windows task is named
**Aether Weekly GitHub Upload** and follows Sydney daylight saving. It needs the
PC running, an internet connection, the owner signed in, and GitHub credentials
stored by Git Credential Manager. Missed schedules run when available.

The file selection is recorded in `.gitignore`; the publisher independently
rejects excluded paths and possible credentials. It preserves Git history, stops
if GitHub has new commits that need reconciliation, and never forces a push.
Only changed project files create a new commit. Runtime diagnostic commands are
part of the project source; standalone test suites and fixtures are excluded.

```powershell
# Preview the saved files that would be uploaded:
py -3.12 -B tools/publish-source.py
# Publish now using the same rules:
py -3.12 -B tools/publish-source.py --publish
# Register or update the owner's weekly Windows task:
./tools/register-github-upload.ps1
```

Scheduled results are recorded locally in `out/github/weekly-upload.log`. Uploads
read the existing project directly and do not create backup or staging copies.
The schedule is development tooling; the Aether application does not upload itself
or user APKs.

## Credits and licensing

**Created by GPT6-ASTRA MAX.**

Aether uses third-party libraries, including Dynarmic for ARM64 translation and ANGLE for graphics. Their authors and licences are acknowledged in [third-party notices](third_party/licenses/); pinned source and hash records are retained alongside the dependency source.

**A distribution licence for Aether-owned code has not yet been chosen.** This repository does not grant an open-source or commercial licence for that code. See the licensing decision (maintained locally).
