# HEADER
# HASH
# 72084b2d1abe995cac35df0322b55b1739bd46e085415f46b71157214f78d1a488ff416a1ef5a5d5ff95ad78baec9e0943e9d84042503d58c5d54926db1b7668
# SIGNATURE
# RC+luDsTEu9+2d4W2O/BB57UV5dnvUjI5uZ1GXcOvh3XrkhvVkKi8sX2Kv6LfzpVvc2MZXl/uI++0O503iUgAg==
# END
# ---

#!/usr/bin/env python3
"""
Apply or manage numbered patches for ./project using files in ./patches.

Patch filenames must begin with an integer ID followed by a dash, e.g.:
  0001-first-change.patch
  0012-fix.diff

Commands:
  - patch [ID ...] : apply all patches in numeric order, or only the specified IDs.
  - rebuild [HASH] : regenerate patch files from git history up to highest existing ID,
                     or only for the given commit HASH (placing it at its historical ID).
  - reset          : hard-reset the repo to the root commit and clear ./patches.

Notes:
  - Applying uses a 3-way merge with relaxed matching and no base-commit checks.
    It still stops on true conflicts. On failure, the repo is rolled back to the
    pre-apply state. Patch files remain for manual fix + amend; rerun rebuild will
    only touch IDs up to the cutoff or the specific ID requested.
"""

VERSION = "0.4.0"

import re
import sys
import shutil
import subprocess
import unicodedata
from pathlib import Path
from typing import List, Tuple, Iterable, Optional, Dict, Set

PATCH_DIR = Path.cwd() / "patches"
PROJECT_DIR = Path.cwd() / "project"

ID_RE = re.compile(r"^(\d+)-")  # capture leading integer before the first dash


def fail(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def run(*args, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def require_ok(cp: subprocess.CompletedProcess, ctx: str) -> None:
    if cp.returncode != 0:
        out = (cp.stdout or "").strip()
        err = (cp.stderr or "").strip()
        fail(f"{ctx} failed\nstdout:\n{out}\nstderr:\n{err}")


def ensure_git_repo(repo: Path):
    if not repo.is_dir():
        fail(f"project directory not found: {repo}")
    cp = run("git", "rev-parse", "--is-inside-work-tree", cwd=repo)
    if cp.returncode != 0 or cp.stdout.strip() != "true":
        fail(f"{repo} is not a git repository.\n{cp.stderr.strip()}")


def ensure_clean_state(repo: Path):
    run("git", "am", "--abort", cwd=repo)
    cp = run("git", "status", "--porcelain", cwd=repo)
    if cp.returncode != 0:
        fail(f"'git status' failed: {cp.stderr.strip()}")
    if cp.stdout.strip():
        fail("working tree not clean. commit or stash changes first.")


def get_root_commit(repo: Path) -> str:
    cp = run("git", "rev-list", "--max-parents=0", "HEAD", cwd=repo)
    require_ok(cp, "find root commit")
    root = cp.stdout.strip().splitlines()[0]
    if not root:
        fail("unable to determine root commit")
    return root


def rev_list_from(repo: Path, base_exclusive: str) -> List[str]:
    # Oldest-first commits after base
    cp = run("git", "rev-list", "--reverse", f"{base_exclusive}..HEAD", cwd=repo)
    require_ok(cp, "rev-list")
    return [l.strip() for l in cp.stdout.splitlines() if l.strip()]


def commit_index_map(repo: Path) -> Dict[str, int]:
    """Map commit sha -> 1-based sequential ID since root."""
    root = get_root_commit(repo)
    commits = rev_list_from(repo, root)
    return {sha: i + 1 for i, sha in enumerate(commits)}


def find_patches(pdir: Path) -> List[Path]:
    if not pdir.is_dir():
        fail(f"patch directory not found: {pdir}")
    items: List[Tuple[int, str, Path]] = []
    for p in sorted(pdir.iterdir()):
        if not p.is_file():
            continue
        m = ID_RE.match(p.name)
        if not m:
            continue
        try:
            pid = int(m.group(1))
        except ValueError:
            continue
        items.append((pid, p.name, p))
    items.sort(key=lambda t: (t[0], t[1]))
    return [p for _, __, p in items]


def highest_patch_id(patches: List[Path]) -> int:
    max_id = 0
    for p in patches:
        m = ID_RE.match(p.name)
        if m:
            try:
                pid = int(m.group(1))
                if pid > max_id:
                    max_id = pid
            except ValueError:
                continue
    return max_id


def sanitize_subject_to_slug(subject: str) -> str:
    s = unicodedata.normalize("NFKD", subject).encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"[^A-Za-z0-9]+", "-", s)
    s = s.strip("-")
    parts = [w.capitalize() for w in s.split("-") if w]
    slug = "-".join(parts) if parts else "Patch"
    return slug[:100]


def write_patch_for_commit(repo: Path, pdir: Path, sha: str, patch_id: int) -> str:
    cp_subj = run("git", "log", "-1", "--pretty=%s", sha, cwd=repo)
    require_ok(cp_subj, f"read subject for {sha}")
    slug = sanitize_subject_to_slug(cp_subj.stdout.strip())

    cp_patch = run(
        "git",
        "format-patch",
        "-1",
        "--stdout",
        "--zero-commit",
        "--no-signature",
        "--no-stat",
        "--full-index",
        "--binary",
        sha,
        cwd=repo,
    )
    require_ok(cp_patch, f"format-patch for {sha}")

    fname = f"{patch_id:04d}-{slug}.patch"
    (pdir / fname).write_text(cp_patch.stdout, encoding="utf-8")
    return fname


def apply_patches(repo: Path, patches: List[Path]):
    if not patches:
        print("no patches found to apply")
        return

    print("patch order:")
    for p in patches:
        print(f"  - {p.name}")

    for p in patches:
        print(f"\napplying: {p.name}")
        cp = run(
            "git",
            "-c", "commit.gpgsign=false",
            "-c", "apply.ignoreWhitespace=change",
            "-c", "apply.whitespace=nowarn",
            "am",
            "-3",
            "-C1",
            "--keep-cr",
            str(p),
            cwd=repo,
        )
        if cp.returncode != 0:
            print((cp.stdout or "").strip())
            print((cp.stderr or "").strip(), file=sys.stderr)
            run("git", "am", "--abort", cwd=repo)
            fail(f"failed to apply {p.name}. repository reset to pre-apply state.")
        else:
            print((cp.stdout or "(applied)").strip())


def rebuild_patches(repo: Path, pdir: Path):
    ensure_clean_state(repo)
    root = get_root_commit(repo)
    commits = rev_list_from(repo, root)

    existing = find_patches(pdir) if pdir.exists() else []
    cutoff = highest_patch_id(existing)
    if cutoff == 0:
        cutoff = len(commits)

    if cutoff == 0:
        print("no commits after root. nothing to rebuild.")
        return

    if cutoff > len(commits):
        cutoff = len(commits)

    if not pdir.exists():
        pdir.mkdir(parents=True)
    else:
        # Remove only IDs <= cutoff
        for p in existing:
            m = ID_RE.match(p.name)
            if not m:
                continue
            if int(m.group(1)) <= cutoff:
                p.unlink(missing_ok=True)

    print(f"rebuilding patches 1..{cutoff}")
    for idx, sha in enumerate(commits[:cutoff], start=1):
        fname = write_patch_for_commit(repo, pdir, sha, idx)
        print(f"  wrote {fname}")
    print("rebuild complete.")


def rebuild_one_commit(repo: Path, pdir: Path, sha: str):
    ensure_clean_state(repo)
    cmap = commit_index_map(repo)
    # Accept short SHA
    matches = [full for full in cmap if full.startswith(sha)]
    if not matches:
        fail(f"commit not found for '{sha}'")
    if len(matches) > 1:
        fail(f"ambiguous hash '{sha}' matches {len(matches)} commits")
    full = matches[0]
    pid = cmap[full]

    if not pdir.exists():
        pdir.mkdir(parents=True)

    # Remove only the target ID
    for p in list(pdir.iterdir()):
        m = ID_RE.match(p.name)
        if m and int(m.group(1)) == pid:
            p.unlink(missing_ok=True)

    fname = write_patch_for_commit(repo, pdir, full, pid)
    print(f"rebuilt ID {pid} from {full[:12]} -> {fname}")


def clear_all_patch_files(pdir: Path):
    if pdir.exists():
        for p in pdir.iterdir():
            if p.is_file():
                p.unlink()
            elif p.is_dir():
                shutil.rmtree(p)
    else:
        pdir.mkdir(parents=True)
    print("cleared ./patches directory.")


def hard_reset_to_root(repo: Path):
    ensure_clean_state(repo)
    root = get_root_commit(repo)
    print(f"hard resetting to root {root}")
    cp = run("git", "reset", "--hard", root, cwd=repo)
    require_ok(cp, "git reset --hard")
    print("reset complete.")


def parse_ids(id_args: List[str]) -> List[int]:
    """Accept IDs like 7, 12, 3-6, 10,12,14 and combine."""
    ids: Set[int] = set()
    tokens: List[str] = []
    for a in id_args:
        tokens.extend([t for t in a.split(",") if t])

    for t in tokens:
        m = re.match(r"^(\d+)-(\d+)$", t)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a > b:
                a, b = b, a
            ids.update(range(a, b + 1))
        else:
            if not re.match(r"^\d+$", t):
                fail(f"invalid patch ID token: '{t}'")
            ids.add(int(t))
    return sorted(ids)


def select_patches_by_ids(pdir: Path, ids: Iterable[int]) -> List[Path]:
    wanted = set(ids)
    selected: List[Tuple[int, str, Path]] = []
    for p in pdir.iterdir():
        if not p.is_file():
            continue
        m = ID_RE.match(p.name)
        if not m:
            continue
        pid = int(m.group(1))
        if pid in wanted:
            selected.append((pid, p.name, p))
    missing = sorted(wanted - {pid for pid, _, _ in selected})
    if missing:
        fail(f"patch IDs not found: {', '.join(str(x) for x in missing)}")
    selected.sort(key=lambda t: (t[0], t[1]))
    return [p for _, __, p in selected]


def main():
    print(f"SOURCE PATCHER v{VERSION}")
    args = sys.argv[1:]

    ensure_git_repo(PROJECT_DIR)

    if not args:
        print("usage:")
        print("  python3 script.py patch [ID ...]")
        print("  python3 script.py rebuild [HASH]")
        print("  python3 script.py reset")
        return

    cmd = args[0].lower()

    if cmd == "patch":
        ensure_clean_state(PROJECT_DIR)
        if len(args) == 1:
            patches = find_patches(PATCH_DIR)
        else:
            ids = parse_ids(args[1:])
            patches = select_patches_by_ids(PATCH_DIR, ids)
        apply_patches(PROJECT_DIR, patches)
        print("\ndone.")
        return

    if cmd == "rebuild":
        if len(args) == 1:
            rebuild_patches(PROJECT_DIR, PATCH_DIR)
        else:
            rebuild_one_commit(PROJECT_DIR, PATCH_DIR, args[1])
        print("\ndone.")
        return

    if cmd == "reset":
        hard_reset_to_root(PROJECT_DIR)
        # clear_all_patch_files(PATCH_DIR)
        print("\ndone.")
        return

    fail(f"unknown command: {cmd}. valid commands: [patch, rebuild, reset]")


if __name__ == "__main__":
    main()