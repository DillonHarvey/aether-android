"""Publish saved project source to the owner's GitHub repository, without copies.

No arguments previews the upload. --publish stages, commits and pushes main.
Only the ordinary repository index is used; there are no alternate checkouts,
temporary payloads, backups, force pushes, merges or automatic write retries.
"""

import argparse
import datetime
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REMOTE = "https://github.com/DillonHarvey/aether-android.git"
ROOT_FILES = {
    ".clang-format",
    ".editorconfig",
    ".gitattributes",
    ".gitignore",
    "CMakeLists.txt",
    "CMakePresets.json",
    "README.md",
}
SOURCE_ROOTS = {"apps", "cmake", "include", "src", "third_party"}
TOOLS = {
    "angle_sources.py",
    "build.ps1",
    "collect-diagnostics.ps1",
    "common.ps1",
    "compile-privacy.py",
    "install.ps1",
    "package-runtime.py",
    "publish-source.py",
    "register-github-upload.ps1",
    "verify-dependencies.py",
    "verify-distribution.py",
}
EXCLUDED_DIRS = {
    "test",
    "tests",
    "testing",
    "unit_test",
    "fixtures",
    "doctest",
    "sample",
    "samples",
    "example",
    "examples",
    "benchmark",
    "benchmarks",
    ".git",
    ".vs",
    "__pycache__",
    "out",
}
EXCLUDED_SUFFIXES = {
    ".md",
    ".markdown",
    ".rst",
    ".ronn",
    ".dox",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".html",
    ".htm",
    ".apk",
    ".apks",
    ".xapk",
    ".apkm",
    ".aab",
    ".dex",
    ".so",
    ".exe",
    ".dll",
    ".pdb",
    ".obj",
    ".lib",
    ".zip",
    ".7z",
    ".tar",
    ".gz",
    ".pfx",
    ".p12",
    ".pem",
    ".key",
    ".keystore",
    ".jks",
    ".pyc",
    ".pyo",
    ".log",
    ".tmp",
    ".bak",
    ".user",
}
SECRET_PATTERN = (
    r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|"
    r"(AKIA|ASIA)[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{35}|"
    r"xox[baprs]-[A-Za-z0-9-]{15,}|"
    r"sk-(proj-|svcacct-)?[A-Za-z0-9_-]{24,}|sk_live_[A-Za-z0-9]{20,}|"
    r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}|"
    r"-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
)

VENDOR_TEST_HELPERS = {
    "core/lightweight_test.hpp",
    "core/lightweight_test_trait.hpp",
    "detail/lightweight_test.hpp",
    "detail/lightweight_test_report.hpp",
    "iostreams/filter/test.hpp",
    "iterator/new_iterator_tests.hpp",
    "math/tools/test_value.hpp",
    "mpl/aux_/test.hpp",
    "numeric/interval/detail/test_input.hpp",
    "pending/iterator_tests.hpp",
}


def permitted(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        return False
    if name in ROOT_FILES:
        return True
    if not path.parts:
        return False
    if (path.name.casefold().startswith(".env")
            or path.name.casefold() in {".netrc", ".git-credentials", "credentials.json", "secrets.json", "id_rsa", "id_ed25519"}):
        return False
    if path.parts[0] == "tools":
        return len(path.parts) == 2 and path.name in TOOLS
    if path.parts[0] not in SOURCE_ROOTS:
        return False
    basename = path.name.casefold()
    if (re.match(r"^(?:readme|changelog|news)(?:[._-]|$)", basename)
            or basename in {"doxyfile", "doxygen.conf", ".codecov.yml"}):
        return False
    if name.startswith((
        "third_party/dynarmic/externals/fmt/support/python/",
        "third_party/dynarmic/externals/zydis/assets/img/",
        "third_party/dynarmic/externals/zydis/assets/screenshots/",
        "third_party/dynarmic/externals/zydis/man/",
    )) or name in {
        "third_party/dynarmic/externals/fmt/support/mkdocs",
        "third_party/dynarmic/externals/fmt/support/mkdocs.yml",
        "third_party/dynarmic/externals/zydis/assets/version-bump-checklist.txt",
    }:
        return False
    if name.removeprefix("third_party/boost/boost/") in VENDOR_TEST_HELPERS:
        return False
    parts = {part.casefold() for part in path.parts}
    if parts & EXCLUDED_DIRS:
        return False
    if path.parts[0] == "third_party" and parts & {"doc", "docs"}:
        return False
    if path.suffix.casefold() in EXCLUDED_SUFFIXES or path.name.startswith(".env"):
        return False
    return not re.search(
        r"(?:_tests?\.(?:cpp|cc|py)$|^test_.*\.(?:py|cpp|c)$)", path.name
    )


def git(*arguments, data=None, allowed=(0,)):
    executable = shutil.which("git")
    if executable is None:
        candidate = (
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "Git/cmd/git.exe"
        )
        if not candidate.is_file():
            raise RuntimeError("Git for Windows is not installed or available on PATH")
        executable = str(candidate)
    environment = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never")
    result = subprocess.run(
        [executable, *arguments],
        cwd=ROOT,
        env=environment,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=900,
        check=False,
    )
    if result.returncode not in allowed:
        # Credential-manager errors contain no secret output; never request credentials here.
        diagnostic = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"git {arguments[0]} failed ({result.returncode}): {diagnostic}"
        )
    return result


def names(output):
    return [part.decode("utf-8") for part in output.split(b"\0") if part]


def validate_names(paths):
    refused = sorted(path for path in paths if not permitted(path))
    if refused:
        raise RuntimeError("Upload contains excluded files: " + ", ".join(refused[:20]))
    required = {
        "README.md",
        "CMakeLists.txt",
        "src/install/privacy_guide.txt",
        "third_party/toolchain-notices.json",
        "tools/publish-source.py",
    }
    if not required.issubset(paths):
        raise RuntimeError(
            "Upload is missing required project files: "
            + ", ".join(sorted(required - set(paths)))
        )


def validate_index():
    entries = names(git("ls-files", "--stage", "-z").stdout)
    paths = []
    for entry in entries:
        metadata, name = entry.split("\t", 1)
        mode, _, stage = metadata.split()
        if stage != "0" or mode not in {"100644", "100755"}:
            raise RuntimeError(f"Conflicted, linked or nested-repository entry: {name}")
        paths.append(name)
    validate_names(paths)
    return paths


def validate_history():
    # A clean current tree is insufficient if an earlier unpushed commit contains private files.
    commits = git("rev-list", "origin/main..HEAD").stdout.decode().splitlines()
    for commit in commits:
        paths = names(git("ls-tree", "-r", "--name-only", "-z", commit).stdout)
        validate_names(paths)


def run(publish):
    if (
        git("rev-parse", "--show-toplevel")
        .stdout.decode()
        .strip()
        .replace("\\", "/")
        .casefold()
        != ROOT.as_posix().casefold()
    ):
        raise RuntimeError("Run from the authoritative Aether repository")
    if git("symbolic-ref", "--short", "HEAD").stdout.decode().strip() != "main":
        raise RuntimeError(
            "The publisher requires the main branch; it never switches branches"
        )
    for option in ((), ("--push",)):
        urls = (
            git("remote", "get-url", *option, "--all", "origin")
            .stdout.decode()
            .splitlines()
        )
        if urls != [REMOTE]:
            raise RuntimeError(
                "origin must have exactly the approved Aether GitHub URL"
            )
    git_dir = Path(git("rev-parse", "--absolute-git-dir").stdout.decode().strip())
    for marker in (
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "rebase-merge",
        "rebase-apply",
        "index.lock",
    ):
        if (git_dir / marker).exists():
            raise RuntimeError("Finish the existing Git operation before publishing")
    if git("diff", "--cached", "--quiet", allowed=(0, 1)).returncode:
        raise RuntimeError(
            "Existing staged changes require review; the publisher will not replace your index"
        )
    paths = sorted(
        set(
            names(
                git(
                    "ls-files", "--cached", "--others", "--exclude-standard", "-z"
                ).stdout
            )
        )
    )
    existing = [path for path in paths if (ROOT / path).exists()]
    validate_names(paths)
    validate_names(existing)
    total = 0
    checked_parents = {ROOT}
    for name in existing:
        path = ROOT / name
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise RuntimeError(f"Upload source is not a normal project file: {name}")
        for parent in path.parents:
            if parent in checked_parents:
                break
            if (
                parent.is_symlink()
                or getattr(parent.lstat(), "st_file_attributes", 0) & 0x400
            ):
                raise RuntimeError(f"Upload source has a linked parent: {name}")
            checked_parents.add(parent)
        if info.st_size >= 100 * 1024 * 1024:
            raise RuntimeError(f"File exceeds GitHub's regular-file size limit: {name}")
        total += info.st_size
    print(
        f"Selected {len(existing):,} project files ({total / 1048576:.1f} MiB); README.md is the only Markdown file.",
        flush=True,
    )
    if not publish:
        print(
            "Preview only. Use --publish to commit and upload these saved project files.",
            flush=True,
        )
        return
    git("fetch", "--no-tags", "origin", "main")
    if git(
        "merge-base", "--is-ancestor", "origin/main", "HEAD", allowed=(0, 1)
    ).returncode:
        raise RuntimeError(
            "GitHub main has new commits; reconcile them manually before the next upload. No merge or force push attempted."
        )
    validate_history()
    git("add", "--all", "--", ".")
    published_paths = validate_index()
    secret_files = git(
        "grep", "--cached", "-I", "-l", "-E", SECRET_PATTERN, allowed=(0, 1)
    )
    if secret_files.returncode == 0:
        raise RuntimeError(
            "Review possible credentials in staged files: "
            + secret_files.stdout.decode().strip()
        )
    if (
        git("diff", "--quiet", allowed=(0, 1)).returncode
        or git("ls-files", "--others", "--exclude-standard", "-z").stdout
    ):
        raise RuntimeError(
            "Project files changed during collection; staged source is retained for review. No commit or upload performed."
        )
    if git("diff", "--cached", "--quiet", allowed=(0, 1)).returncode:
        date = datetime.datetime.now().astimezone().isoformat(timespec="minutes")
        git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            f"Update Aether project source ({date})",
        )
    else:
        print("No saved project changes to commit.", flush=True)
    validate_history()
    commit = git("rev-parse", "HEAD").stdout.decode().strip()
    git("push", "--porcelain", "origin", "HEAD:refs/heads/main")
    remote = git("ls-remote", "origin", "refs/heads/main").stdout.decode().split()
    if not remote or remote[0] != commit:
        raise RuntimeError(
            "Push returned, but GitHub main does not match the published commit; inspect before retrying"
        )
    print(
        f"Verified GitHub main at {commit}; {len(published_paths):,} source files. Local tests, documents and APKs remain on disk.",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true")
    parser.add_argument(
        "--log",
        action="store_true",
        help="Append results to out/github/weekly-upload.log",
    )
    args = parser.parse_args()
    log = None
    try:
        if args.log:
            folder = ROOT / "out/github"
            folder.mkdir(parents=True, exist_ok=True)
            log = (folder / "weekly-upload.log").open(
                "a", encoding="utf-8", buffering=1
            )
            sys.stdout = sys.stderr = log
        print(
            "Aether source upload: " + datetime.datetime.now().astimezone().isoformat(),
            flush=True,
        )
        run(args.publish)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print("UPLOAD FAILED: " + str(error), file=sys.stderr, flush=True)
        return 1
    finally:
        if log is not None:
            sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__
            log.close()


if __name__ == "__main__":
    raise SystemExit(main())
