#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


TOOL_DIR = Path(__file__).resolve().parent
HOOK_MARKER = "# managed-by: pre-push-check"
DEFAULT_HOOK = "pre-push"

IGNORE_FILE_NAME = ".pre-push-check-ignore.md"
IGNORE_TABLE_HEADER = "| 済 | ID | 重大度 | 種別 | 検出箇所 | 説明 | 検出内容 |"
IGNORE_TABLE_SEP = "|---|---|---|---|---|---|---|"
IGNORE_ROW_PATTERN = re.compile(
    r"^\|\s*\[([ xX])\]\s*\|\s*([0-9a-f]{12})\s*\|\s*([^|]*)\|\s*([^|]*)\|\s*([^|]*)\|\s*([^|]*)\|\s*(.*?)\s*\|\s*$"
)
# Kinds with no specific location/content to anchor a fingerprint to (a plain yes/no repo-state
# check, not "these files/this file are the reason"). "command" in particular only carries
# "<label> failed with exit code N", not which assertion or file actually failed, so a checked-off
# row would silently swallow a different, unrelated future failure of the same command. These are
# always reported fresh and never enter the ignore table.
NON_SUPPRESSIBLE_KINDS = {"upstream", "remote", "command"}

SECRET_PATTERN = re.compile(
    r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:api[_-]?key|password|token)\s*(?::(?!=)|=(?!=)))",
    re.IGNORECASE,
)
CONFLICT_PATTERN = re.compile(r"^(<<<<<<<|=======|>>>>>>>)")
DEBUG_PATTERN = re.compile(
    r"(console\.log\(|\bdebugger\b|fmt\.Println\(|Write-Host\b|dbg!\(|var_dump\()"  # pre-push-check: ignore-debug
)
DEBUG_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".ps1",
    ".psm1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".ts",
    ".tsx",
}
GENERATED_PARTS = {
    ".pytest_cache",
    "__pycache__",
    "bin",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "obj",
    "target",
    "vendor",
}
LARGE_FILE_BYTES = 5 * 1024 * 1024

LOCAL_PATH_PATTERN = re.compile(
    r"(/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+|C:\\Users\\[A-Za-z0-9._ -]+)",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+$")
PRIVATE_EMAIL_DOMAINS = {"gmail.com", "icloud.com", "outlook.com", "hotmail.com", "yahoo.com"}
GITIGNORE_PATTERNS = {
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "__pycache__/",
    "node_modules/",
    "dist/",
    "build/",
    "target/",
    "bin/",
    "obj/",
}
DECLARED_COMMAND_TARGETS = ("lint", "typecheck", "check", "build", "test")
SHELL_EXTENSIONS = {".sh", ".bash", ".zsh"}
POWERSHELL_EXTENSIONS = {".ps1", ".psm1", ".psd1"}


@dataclass
class Finding:
    severity: str
    kind: str
    location: str
    message: str
    recommendation: str
    detail: str = ""


@dataclass
class CheckRun:
    label: str
    status: str
    detail: str = ""


@dataclass
class Context:
    repo: Path
    branch: str
    upstream: str | None
    push_range: str
    commit_count: int
    changed_files: int
    status: str
    remotes: str


@dataclass
class Report:
    context: Context
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckRun] = field(default_factory=list)
    executed_commands: set[tuple[str, ...]] = field(default_factory=set)

    @property
    def verdict(self) -> str:
        if any(f.severity == "Blocker" for f in self.findings):
            return "要修正（Blocker あり）"
        if any(f.severity == "Warning" for f in self.findings):
            return "要判断（Warning・確認事項あり）"
        return "PUSH 可"


def finding_fingerprint(finding: Finding) -> str:
    digest = hashlib.sha1(
        f"{finding.kind}\x1f{finding.location}\x1f{finding.message}\x1f{finding.detail}".encode("utf-8")
    ).hexdigest()
    return digest[:12]


def is_suppressible(finding: Finding) -> bool:
    return finding.kind not in NON_SUPPRESSIBLE_KINDS


def ignore_file_path(repo: Path) -> Path:
    return repo / IGNORE_FILE_NAME


def escape_table_cell(text: str) -> str:
    return text.replace("|", "\\|")


def parse_ignore_table(path: Path) -> dict[str, tuple[bool, str, str, str, str, str]]:
    rows: dict[str, tuple[bool, str, str, str, str, str]] = {}
    for line in read_text_if_exists(path).splitlines():
        match = IGNORE_ROW_PATTERN.match(line)
        if not match:
            continue
        checked = match.group(1).lower() == "x"
        fingerprint = match.group(2)
        severity, kind, location, message, detail = (g.strip() for g in match.groups()[2:])
        rows[fingerprint] = (checked, severity, kind, location, message, detail)
    return rows


def render_ignore_table(rows: dict[str, tuple[bool, str, str, str, str, str]]) -> str:
    lines = [
        "# pre-push-check 誤検知一覧",
        "",
        "このファイルは pre-push-check が自動生成・更新します。",
        "誤検知だと判断した行の `[ ]` を `[x]` に変更すると、以後その指摘は無視されます。",
        "このファイルは `.gitignore` に自動追加されるため、リポジトリには含まれません（ローカル限定の判断です）。",
        "",
        IGNORE_TABLE_HEADER,
        IGNORE_TABLE_SEP,
    ]
    for fingerprint, (checked, severity, kind, location, message, detail) in rows.items():
        box = "[x]" if checked else "[ ]"
        lines.append(
            f"| {box} | {fingerprint} | {escape_table_cell(severity)} | {escape_table_cell(kind)} | "
            f"{escape_table_cell(location)} | {escape_table_cell(message)} | {escape_table_cell(detail)} |"
        )
    lines.append("")
    return "\n".join(lines)


def ensure_gitignore_entry(repo: Path) -> None:
    gitignore = repo / ".gitignore"
    text = read_text_if_exists(gitignore)
    if any(line.strip() == IGNORE_FILE_NAME for line in text.splitlines()):
        return
    prefix = "" if not text or text.endswith("\n") else "\n"
    with gitignore.open("a", encoding="utf-8") as fh:
        fh.write(f"{prefix}{IGNORE_FILE_NAME}\n")


def sync_ignore_file(repo: Path, findings: list[Finding]) -> tuple[dict[str, bool], int, int]:
    path = ignore_file_path(repo)
    existing_rows = parse_ignore_table(path)
    suppressible = [f for f in findings if is_suppressible(f)]
    current_fingerprints = {finding_fingerprint(f) for f in suppressible}
    rows = {fp: row for fp, row in existing_rows.items() if fp in current_fingerprints}
    removed = len(existing_rows) - len(rows)
    added = 0
    for finding in suppressible:
        fingerprint = finding_fingerprint(finding)
        if fingerprint not in rows:
            rows[fingerprint] = (
                False,
                finding.severity,
                finding.kind,
                finding.location,
                finding.message,
                finding.detail,
            )
            added += 1
    if added or removed:
        if rows:
            path.write_text(render_ignore_table(rows), encoding="utf-8")
        elif path.exists():
            path.unlink()
    ensure_gitignore_entry(repo)
    return {fingerprint: row[0] for fingerprint, row in rows.items()}, added, removed


def run(
    command: list[str],
    cwd: Path,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def git(repo: Path, args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    return run(["git", *args], repo, check)


def repo_root(path: Path) -> Path:
    proc = run(["git", "rev-parse", "--show-toplevel"], path)
    if proc.returncode != 0:
        raise SystemExit(f"not a git repository: {path}")
    return Path(proc.stdout.strip()).resolve()


def git_output(repo: Path, args: list[str]) -> str:
    proc = git(repo, args)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def tracked_files(repo: Path) -> list[str]:
    proc = git(repo, ["ls-files"])
    if proc.returncode != 0:
        return []
    return [line for line in proc.stdout.splitlines() if line]


def path_matches_any(name: str, patterns: Iterable[str]) -> bool:
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    for pattern in patterns:
        clean = pattern.rstrip("/")
        if pattern.endswith("/") and clean in parts:
            return True
        if fnmatch.fnmatch(normalized, pattern) or any(fnmatch.fnmatch(part, clean) for part in parts):
            return True
    return False


def has_file(repo: Path, *names: str) -> bool:
    return any((repo / name).exists() for name in names)


def has_suffix(repo: Path, suffixes: Iterable[str]) -> bool:
    suffix_set = set(suffixes)
    return any((repo / name).suffix in suffix_set for name in tracked_files(repo))


def read_text_if_exists(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def make_target_exists(repo: Path, target: str) -> bool:
    makefile = repo / "Makefile"
    if not makefile.exists():
        makefile = repo / "makefile"
    text = read_text_if_exists(makefile)
    return bool(re.search(rf"^(?:[A-Za-z0-9_.-]+\s+)*{re.escape(target)}\s*:", text, re.MULTILINE))


def just_recipe_exists(repo: Path, target: str) -> bool:
    justfile = repo / "justfile"
    if not justfile.exists():
        justfile = repo / "Justfile"
    text = read_text_if_exists(justfile)
    return bool(re.search(rf"^{re.escape(target)}(?:\s|:)", text, re.MULTILINE))


def build_context(repo: Path) -> Context:
    branch = git_output(repo, ["rev-parse", "--abbrev-ref", "HEAD"]) or "unknown"
    upstream_proc = git(repo, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    upstream = upstream_proc.stdout.strip() if upstream_proc.returncode == 0 else None
    push_range = f"{upstream}..HEAD" if upstream else "HEAD"
    commit_count_text = git_output(repo, ["rev-list", "--count", push_range])
    if upstream:
        changed_files_text = git_output(repo, ["diff", "--name-only", push_range])
    else:
        changed_files_text = git_output(repo, ["ls-files"])
    return Context(
        repo=repo,
        branch=branch,
        upstream=upstream,
        push_range=push_range,
        commit_count=int(commit_count_text or "0"),
        changed_files=len([line for line in changed_files_text.splitlines() if line]),
        status=git_output(repo, ["status", "--short"]),
        remotes=git_output(repo, ["remote", "-v"]),
    )


def add_command_check(report: Report, label: str, command: list[str], cwd: Path, blocker: bool = True) -> None:
    key = tuple(command)
    if key in report.executed_commands:
        report.checks.append(CheckRun(label, "skipped", "same command already executed"))
        return
    report.executed_commands.add(key)
    proc = run(command, cwd)
    detail = proc.stdout.strip()
    if proc.returncode == 0:
        report.checks.append(CheckRun(label, "ok"))
        return
    if len(detail) > 1000:
        detail = f"{detail[:1000]}\n... truncated ..."
    report.checks.append(CheckRun(label, "failed", detail))
    report.findings.append(
        Finding(
            "Blocker" if blocker else "Warning",
            "command",
            ".",
            f"`{label}` failed with exit code {proc.returncode}",
            "Fix the failing command before pushing.",
        )
    )


def add_skipped(report: Report, label: str, reason: str) -> None:
    report.checks.append(CheckRun(label, "skipped", reason))


def iter_text_files(repo: Path) -> Iterable[Path]:
    for name in tracked_files(repo):
        path = repo / name
        if not path.is_file():
            continue
        try:
            with path.open("rb") as fh:
                chunk = fh.read(8192)
            if b"\0" in chunk:
                continue
        except OSError:
            continue
        yield path


def scan_worktree(report: Report) -> None:
    secret_hits = 0
    conflict_hits = 0
    debug_hits = 0
    for path in iter_text_files(report.context.repo):
        rel = path.relative_to(report.context.repo).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            location = f"{rel}:{lineno}"
            if SECRET_PATTERN.search(line):
                secret_hits += 1
                report.findings.append(
                    Finding("Blocker", "secret", location, "Possible secret in tracked file.", "Remove it and rotate the credential if real.", line.strip())
                )
            if CONFLICT_PATTERN.search(line):
                conflict_hits += 1
                report.findings.append(
                    Finding("Blocker", "conflict", location, "Conflict marker remains.", "Resolve the merge conflict before pushing.", line.strip())
                )
            if path.suffix in DEBUG_EXTENSIONS and "pre-push-check: ignore-debug" not in line and DEBUG_PATTERN.search(line):
                debug_hits += 1
                report.findings.append(
                    Finding("Warning", "debug", location, "Possible debug remnant.", "Confirm it is intentional or remove it.", line.strip())
                )
    report.checks.append(CheckRun("scan tracked files for secrets", "ok", f"hits={secret_hits}"))
    report.checks.append(CheckRun("scan tracked files for conflict markers", "ok", f"hits={conflict_hits}"))
    report.checks.append(CheckRun("scan tracked files for debug remnants", "ok", f"hits={debug_hits}"))


def scan_history(report: Report) -> None:
    if command_exists("gitleaks"):
        add_command_check(report, "gitleaks detect", ["gitleaks", "detect", "--source", str(report.context.repo)], report.context.repo)
        return

    pattern = SECRET_PATTERN.pattern
    proc = git(report.context.repo, ["log", report.context.push_range, "-G", pattern, "--oneline"])
    if proc.returncode == 0 and proc.stdout.strip():
        for line in proc.stdout.strip().splitlines()[:20]:
            report.findings.append(
                Finding("Blocker", "secret-history", "git history", f"Possible secret-like change in `{line}`.", "Inspect history and rotate credentials if real.")
            )
        report.checks.append(CheckRun("scan push history for secrets", "failed", "fallback git log -G found matches"))
    else:
        report.checks.append(CheckRun("scan push history for secrets", "ok", "fallback git log -G"))
    add_skipped(report, "gitleaks detect", "gitleaks is not installed")


def scan_git_metadata(report: Report) -> None:
    if report.context.status:
        # Use raw (unstripped) output: report.context.status has been .strip()-ed, which eats the
        # leading status-code column of the first line and misaligns the fixed-width slice below.
        raw_status = git(report.context.repo, ["status", "--short"]).stdout
        dirty_paths = ", ".join(
            line[3:].strip() for line in raw_status.splitlines() if len(line) > 3
        ) or "."
        report.findings.append(
            Finding("Note", "dirty-worktree", dirty_paths, "Working tree has uncommitted changes.", "Confirm they are intentionally excluded from this push.")
        )
    if not report.context.upstream:
        report.findings.append(
            Finding("Warning", "upstream", ".", "No upstream branch is configured.", "Confirm the first push target explicitly.")
        )

    log = git_output(report.context.repo, ["log", report.context.push_range, "--format=%h %s"])
    for line in log.splitlines():
        if re.search(r"\b(WIP|fixup!|squash!)\b", line, re.IGNORECASE):
            report.findings.append(
                Finding("Warning", "history", "git log", f"Unpolished commit subject: `{line}`.", "Squash or reword before publishing if unintended.")
            )
    report.checks.append(CheckRun("inspect git status and push range", "ok"))


def scan_remote_publicity(report: Report) -> None:
    remotes = report.context.remotes
    if not remotes:
        report.findings.append(
            Finding("Warning", "remote", ".", "No Git remote is configured.", "Confirm the destination before first publication.")
        )
        report.checks.append(CheckRun("inspect remotes", "ok", "remotes=0"))
        return
    public_like = any(host in remotes for host in ("github.com", "gitlab.com", "bitbucket.org"))
    if public_like:
        report.findings.append(
            Finding("Note", "publication", "git remote", "Remote appears to be on a public hosting service.", "Confirm the repository visibility and data classification before pushing.")
        )
    report.checks.append(CheckRun("inspect remotes", "ok", f"public-hosting={str(public_like).lower()}"))


def scan_tracked_paths(report: Report) -> None:
    proc = git(report.context.repo, ["ls-files", "-s"])
    generated_hits = 0
    large_hits = 0
    for line in proc.stdout.splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) != 4:
            continue
        object_id = parts[1]
        name = parts[3]
        path_parts = set(Path(name).parts)
        if path_parts & GENERATED_PARTS or name.endswith((".bak", ".orig", ".tmp", ".pyc")):
            generated_hits += 1
            report.findings.append(
                Finding("Warning", "generated", name, "Generated or temporary file is tracked.", "Remove it from Git or document why it is source.")
            )
        size_text = git_output(report.context.repo, ["cat-file", "-s", object_id])
        if size_text.isdigit() and int(size_text) > LARGE_FILE_BYTES:
            large_hits += 1
            report.findings.append(
                Finding("Warning", "large-file", name, f"Tracked file is larger than {LARGE_FILE_BYTES // 1024 // 1024} MiB.", "Use release assets or Git LFS if needed.")
            )
    report.checks.append(CheckRun("scan tracked paths for generated files", "ok", f"hits={generated_hits}"))
    report.checks.append(CheckRun("scan tracked paths for large files", "ok", f"hits={large_hits}"))


def scan_history_quality(report: Report) -> None:
    repo = report.context.repo
    authors = git_output(repo, ["log", report.context.push_range, "--format=%an <%ae>"])
    seen: set[str] = set()
    email_warnings = 0
    for line in authors.splitlines():
        if line in seen:
            continue
        seen.add(line)
        match = re.search(r"<([^>]+)>", line)
        if not match:
            continue
        email = match.group(1)
        domain = email.rsplit("@", 1)[-1].lower() if EMAIL_PATTERN.match(email) else ""
        if domain in PRIVATE_EMAIL_DOMAINS:
            email_warnings += 1
            report.findings.append(
                Finding("Warning", "author-email", "git log", f"Commit author uses a common personal email: `{line}`.", "Confirm this identity is intended for a public push.")
            )

    merge_commits = git_output(repo, ["log", report.context.push_range, "--merges", "--oneline"])
    merge_count = 0
    for line in merge_commits.splitlines():
        merge_count += 1
        report.findings.append(
            Finding("Warning", "history", "git log", f"Merge commit in push range: `{line}`.", "Confirm the branch history is intentionally unsquashed.")
        )

    report.checks.append(CheckRun("inspect commit authors", "ok", f"personal-email-warnings={email_warnings}"))
    report.checks.append(CheckRun("inspect merge commits", "ok", f"merge-commits={merge_count}"))


def scan_gitignore_coverage(report: Report) -> None:
    repo = report.context.repo
    gitignore = read_text_if_exists(repo / ".gitignore")
    ignored = [line.strip() for line in gitignore.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    expected = set(GITIGNORE_PATTERNS)
    files = tracked_files(repo)
    if not any((repo / "package.json").exists() or name.endswith((".js", ".ts", ".jsx", ".tsx")) for name in files):
        expected -= {"node_modules/", "dist/"}
    if not any((repo / name).exists() for name in ("pyproject.toml", "requirements.txt", "setup.py")):
        expected -= {"__pycache__/"}
    if not (repo / "Cargo.toml").exists():
        expected -= {"target/"}
    if not has_suffix(repo, {".csproj", ".sln"}):
        expected -= {"bin/", "obj/"}
    missing = sorted(pattern for pattern in expected if pattern not in ignored)
    if missing:
        shown = ", ".join(missing[:8])
        if len(missing) > 8:
            shown += ", ..."
        report.findings.append(
            Finding("Note", ".gitignore", ".gitignore", f"Common ignore patterns are missing: {shown}.", "Add patterns that fit this repository's stack.")
        )
    for name in files:
        if name.startswith(".env"):
            report.findings.append(
                Finding("Blocker", ".env", name, "An environment file is tracked.", "Remove it from Git and rotate any real credentials.")
            )
    report.checks.append(CheckRun("inspect .gitignore coverage", "ok", f"missing={len(missing)}"))


def scan_local_paths(report: Report) -> None:
    hits = 0
    for path in iter_text_files(report.context.repo):
        rel = path.relative_to(report.context.repo).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            if LOCAL_PATH_PATTERN.search(line):
                hits += 1
                report.findings.append(
                    Finding("Warning", "local-path", f"{rel}:{lineno}", "Local absolute path appears in a tracked file.", "Replace it with a relative path or configuration.", line.strip())
                )
    report.checks.append(CheckRun("scan tracked files for local paths", "ok", f"hits={hits}"))


def scan_history_file_shapes(report: Report) -> None:
    repo = report.context.repo
    changed = git_output(repo, ["diff", "--name-only", report.context.push_range]) if report.context.upstream else "\n".join(tracked_files(repo))
    generated = 0
    for name in changed.splitlines():
        if path_matches_any(name, GENERATED_PARTS) or name.endswith((".bak", ".orig", ".tmp", ".pyc")):
            generated += 1
            report.findings.append(
                Finding("Warning", "history-file", name, "Push range includes generated or temporary path.", "Remove generated artifacts unless they are intentionally versioned.")
            )
    report.checks.append(CheckRun("inspect pushed file paths", "ok", f"generated-or-temp={generated}"))




def package_json_scripts(repo: Path) -> dict[str, str]:
    path = repo / "package.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    scripts = data.get("scripts", {})
    return scripts if isinstance(scripts, dict) else {}


def node_runner(repo: Path) -> tuple[str, list[str]]:
    if (repo / "pnpm-lock.yaml").exists():
        return "pnpm", ["pnpm", "run"]
    if (repo / "yarn.lock").exists():
        return "yarn", ["yarn"]
    if (repo / "bun.lockb").exists() or (repo / "bun.lock").exists():
        return "bun", ["bun", "run"]
    return "npm", ["npm", "run"]


def run_declared_node_checks(report: Report) -> None:
    repo = report.context.repo
    scripts = package_json_scripts(repo)
    if not scripts:
        return
    binary, runner = node_runner(repo)
    if not command_exists(binary):
        add_skipped(report, f"{binary} scripts", f"{binary} is not installed")
        return
    for name in DECLARED_COMMAND_TARGETS:
        if name in scripts:
            add_command_check(report, f"{binary} run {name}", [*runner, name], repo)
    lockfiles = [name for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb") if (repo / name).exists()]
    if lockfiles:
        report.checks.append(CheckRun("inspect Node lockfile", "ok", ", ".join(lockfiles)))
    else:
        report.findings.append(Finding("Warning", "dependencies", "package.json", "Node project has no recognized lockfile.", "Commit a package manager lockfile before publishing."))
        report.checks.append(CheckRun("inspect Node lockfile", "failed", "no lockfile"))


def run_python_checks(report: Report) -> None:
    repo = report.context.repo
    if not any((repo / name).exists() for name in ("pyproject.toml", "requirements.txt", "setup.py")):
        return
    if command_exists("ruff"):
        add_command_check(report, "ruff format --check .", ["ruff", "format", "--check", "."], repo)
        add_command_check(report, "ruff check .", ["ruff", "check", "."], repo)
    else:
        add_skipped(report, "ruff", "ruff is not installed")
    if command_exists("pytest"):
        add_command_check(report, "pytest", ["pytest"], repo)
    else:
        add_skipped(report, "pytest", "pytest is not installed")


def run_go_checks(report: Report) -> None:
    repo = report.context.repo
    if not (repo / "go.mod").exists():
        return
    if not command_exists("go"):
        add_skipped(report, "go checks", "go is not installed")
        return
    if command_exists("gofmt"):
        go_files = [p.relative_to(repo).as_posix() for p in repo.rglob("*.go") if ".git" not in p.parts and "vendor" not in p.parts]
        if go_files:
            proc = run(["gofmt", "-l", *go_files], repo)
            status = "ok" if proc.returncode == 0 and not proc.stdout.strip() else "failed"
            report.checks.append(CheckRun("gofmt -l", status, proc.stdout.strip()))
            if status == "failed":
                unformatted = ", ".join(proc.stdout.split()) or "."
                report.findings.append(Finding("Blocker", "format", unformatted, "Go files are not gofmt-formatted.", "Run gofmt before pushing."))
    add_command_check(report, "go vet ./...", ["go", "vet", "./..."], repo)
    add_command_check(report, "go test ./...", ["go", "test", "./..."], repo)


def run_rust_checks(report: Report) -> None:
    repo = report.context.repo
    if not (repo / "Cargo.toml").exists():
        return
    if not command_exists("cargo"):
        add_skipped(report, "cargo checks", "cargo is not installed")
        return
    add_command_check(report, "cargo fmt --check", ["cargo", "fmt", "--check"], repo)
    add_command_check(report, "cargo clippy -- -D warnings", ["cargo", "clippy", "--", "-D", "warnings"], repo)
    add_command_check(report, "cargo test", ["cargo", "test"], repo)


def safe_ci_command_from_line(line: str) -> list[str] | None:
    stripped = line.strip()
    if stripped.startswith("- "):
        stripped = stripped[2:].strip()
    if not stripped.startswith("run:"):
        return None
    command_text = stripped.removeprefix("run:").strip().strip('"\'')
    if not command_text or any(token in command_text for token in ("&&", "||", ";", "|", "$", "`", "<", ">")):
        return None
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return None
    if not parts:
        return None
    safe_prefixes = (
        ("npm", "run", "lint"),
        ("npm", "run", "typecheck"),
        ("npm", "run", "check"),
        ("npm", "run", "build"),
        ("npm", "test"),
        ("pnpm", "run", "lint"),
        ("pnpm", "run", "typecheck"),
        ("pnpm", "run", "check"),
        ("pnpm", "run", "build"),
        ("pnpm", "test"),
        ("yarn", "lint"),
        ("yarn", "typecheck"),
        ("yarn", "check"),
        ("yarn", "build"),
        ("yarn", "test"),
        ("bun", "run", "lint"),
        ("bun", "run", "typecheck"),
        ("bun", "run", "check"),
        ("bun", "run", "build"),
        ("bun", "test"),
        ("pytest",),
        ("python", "-m", "pytest"),
        ("python3", "-m", "pytest"),
        ("go", "test", "./..."),
        ("go", "vet", "./..."),
        ("cargo", "fmt", "--check"),
        ("cargo", "clippy"),
        ("cargo", "test"),
        ("cargo", "build"),
        ("make", "lint"),
        ("make", "check"),
        ("make", "build"),
        ("make", "test"),
    )
    for prefix in safe_prefixes:
        if tuple(parts[: len(prefix)]) == prefix:
            return parts
    return None


def run_ci_declared_checks(report: Report, workflow_commands: list[list[str]]) -> None:
    repo = report.context.repo
    seen: set[tuple[str, ...]] = set()
    adopted = 0
    for command in workflow_commands:
        key = tuple(command)
        if key in seen:
            continue
        seen.add(key)
        if not command_exists(command[0]):
            add_skipped(report, f"CI declared: {' '.join(command)}", f"{command[0]} is not installed")
            continue
        adopted += 1
        add_command_check(report, f"CI declared: {' '.join(command)}", command, repo)
    report.checks.append(CheckRun("adopt CI declared commands", "ok", f"commands={adopted}"))


def scan_ci(report: Report) -> None:
    workflow_dir = report.context.repo / ".github" / "workflows"
    if not workflow_dir.exists():
        add_skipped(report, "inspect GitHub Actions", ".github/workflows does not exist")
        return
    workflow_commands: list[list[str]] = []
    for workflow in workflow_dir.glob("*.y*ml"):
        try:
            lines = workflow.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            location = f"{workflow.relative_to(report.context.repo).as_posix()}:{lineno}"
            if "pull_request_target" in stripped:
                report.findings.append(Finding("Warning", "ci", location, "`pull_request_target` is used.", "Confirm this is safe for untrusted PRs.", stripped))
            if re.search(r"uses:\s+[^@\s]+/[^@\s]+@v?\d+", stripped):
                report.findings.append(Finding("Warning", "ci", location, "Third-party action is pinned only by tag.", "Pin actions to commit SHA for stronger supply-chain safety.", stripped))
            if re.search(r"echo\s+.*secrets\.", stripped, re.IGNORECASE):
                report.findings.append(Finding("Blocker", "ci-secret", location, "Workflow may echo a secret.", "Do not print secrets in CI logs.", stripped))
            command = safe_ci_command_from_line(stripped)
            if command:
                workflow_commands.append(command)
    report.checks.append(CheckRun("inspect GitHub Actions", "ok"))
    run_ci_declared_checks(report, workflow_commands)
    if command_exists("gh"):
        proc = run(["gh", "run", "list", "--limit", "5"], report.context.repo)
        status = "ok" if proc.returncode == 0 else "skipped"
        detail = "recent runs available" if proc.returncode == 0 else "gh is installed but recent runs could not be queried"
        report.checks.append(CheckRun("inspect recent GitHub Actions runs", status, detail))
    else:
        add_skipped(report, "inspect recent GitHub Actions runs", "gh is not installed")


def run_java_checks(report: Report) -> None:
    repo = report.context.repo
    if not has_file(repo, "pom.xml", "build.gradle", "build.gradle.kts"):
        return
    if (repo / "gradlew").exists():
        add_command_check(report, "./gradlew build", ["./gradlew", "build"], repo)
    elif (repo / "mvnw").exists():
        add_command_check(report, "./mvnw verify", ["./mvnw", "verify"], repo)
    elif command_exists("gradle") and has_file(repo, "build.gradle", "build.gradle.kts"):
        add_command_check(report, "gradle build", ["gradle", "build"], repo)
    elif command_exists("mvn") and has_file(repo, "pom.xml"):
        add_command_check(report, "mvn verify", ["mvn", "verify"], repo)
    else:
        add_skipped(report, "Java build", "no Gradle/Maven wrapper or system tool is available")


def run_dotnet_checks(report: Report) -> None:
    repo = report.context.repo
    if not has_suffix(repo, {".csproj", ".sln"}):
        return
    if not command_exists("dotnet"):
        add_skipped(report, ".NET checks", "dotnet is not installed")
        return
    add_command_check(report, "dotnet build -warnaserror", ["dotnet", "build", "-warnaserror"], repo)
    add_command_check(report, "dotnet test", ["dotnet", "test"], repo)


def run_cpp_checks(report: Report) -> None:
    repo = report.context.repo
    if not (has_file(repo, "CMakeLists.txt", "Makefile", "makefile") or has_suffix(repo, {".c", ".cc", ".cpp", ".h", ".hpp"})):
        return
    if command_exists("cmake") and (repo / "build").exists():
        add_command_check(report, "cmake --build build", ["cmake", "--build", "build"], repo)


def run_ruby_checks(report: Report) -> None:
    repo = report.context.repo
    if not (has_file(repo, "Gemfile") or has_suffix(repo, {".rb"})):
        return
    if command_exists("ruby"):
        for name in tracked_files(repo):
            if name.endswith(".rb"):
                add_command_check(report, f"ruby -c {name}", ["ruby", "-c", name], repo)
    else:
        add_skipped(report, "ruby syntax", "ruby is not installed")
    if command_exists("bundle") and has_file(repo, "Gemfile"):
        if make_target_exists(repo, "test"):
            return
        add_command_check(report, "bundle exec rspec", ["bundle", "exec", "rspec"], repo, blocker=False)


def run_php_checks(report: Report) -> None:
    repo = report.context.repo
    if not (has_file(repo, "composer.json") or has_suffix(repo, {".php"})):
        return
    if command_exists("php"):
        for name in tracked_files(repo):
            if name.endswith(".php"):
                add_command_check(report, f"php -l {name}", ["php", "-l", name], repo)
    else:
        add_skipped(report, "php syntax", "php is not installed")
    if command_exists("composer") and has_file(repo, "composer.json"):
        add_command_check(report, "composer validate", ["composer", "validate", "--strict"], repo)


def run_shell_checks(report: Report) -> None:
    repo = report.context.repo
    shell_files = [name for name in tracked_files(repo) if Path(name).suffix in SHELL_EXTENSIONS]
    if not shell_files:
        return
    if command_exists("bash"):
        for name in shell_files:
            add_command_check(report, f"bash -n {name}", ["bash", "-n", name], repo)
    else:
        add_skipped(report, "shell syntax", "bash is not installed")
    if command_exists("shellcheck"):
        add_command_check(report, "shellcheck", ["shellcheck", *shell_files], repo, blocker=False)
    else:
        add_skipped(report, "shellcheck", "shellcheck is not installed")


def run_powershell_checks(report: Report) -> None:
    repo = report.context.repo
    ps_files = [name for name in tracked_files(repo) if Path(name).suffix.lower() in POWERSHELL_EXTENSIONS]
    if not ps_files:
        return
    pwsh = "pwsh" if command_exists("pwsh") else "powershell" if command_exists("powershell") else ""
    if not pwsh:
        add_skipped(report, "PowerShell parser", "pwsh/powershell is not installed")
        return
    for name in ps_files:
        command = "$ErrorActionPreference='Stop'; [System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$null, [ref]$errors) | Out-Null; if ($errors.Count) { $errors | ForEach-Object ToString; exit 1 }"
        add_command_check(report, f"PowerShell parse {name}", [pwsh, "-NoProfile", "-Command", command, name], repo)


def run_declared_make_just_checks(report: Report) -> None:
    repo = report.context.repo
    if command_exists("just") and ((repo / "justfile").exists() or (repo / "Justfile").exists()):
        for target in DECLARED_COMMAND_TARGETS:
            if just_recipe_exists(repo, target):
                add_command_check(report, f"just {target}", ["just", target], repo)
    elif (repo / "justfile").exists() or (repo / "Justfile").exists():
        add_skipped(report, "just recipes", "just is not installed")

    if (repo / "Makefile").exists() or (repo / "makefile").exists():
        if not command_exists("make"):
            add_skipped(report, "Makefile targets", "make is not installed")
            return
        for target in DECLARED_COMMAND_TARGETS:
            if make_target_exists(repo, target):
                add_command_check(report, f"make {target}", ["make", target], repo)




def run_stack_checks(report: Report) -> None:
    run_declared_make_just_checks(report)
    run_declared_node_checks(report)
    run_python_checks(report)
    run_go_checks(report)
    run_rust_checks(report)
    run_java_checks(report)
    run_dotnet_checks(report)
    run_cpp_checks(report)
    run_ruby_checks(report)
    run_php_checks(report)
    run_shell_checks(report)
    run_powershell_checks(report)


def make_report(repo: Path) -> Report:
    report = Report(build_context(repo))
    scan_git_metadata(report)
    scan_remote_publicity(report)
    scan_history(report)
    scan_history_quality(report)
    scan_history_file_shapes(report)
    scan_worktree(report)
    scan_local_paths(report)
    scan_tracked_paths(report)
    scan_gitignore_coverage(report)
    scan_ci(report)
    run_stack_checks(report)
    return report


def print_report(
    report: Report,
    suppressed: list[Finding] | None = None,
    added: int = 0,
    removed: int = 0,
) -> None:
    ctx = report.context
    print(report.verdict)
    print()
    print(f"repo: {ctx.repo}")
    print(f"branch: {ctx.branch}")
    print(f"upstream: {ctx.upstream or '(none)'}")
    print(f"push range: {ctx.push_range}")
    print(f"commits: {ctx.commit_count}")
    print(f"changed files in range: {ctx.changed_files}")
    if ctx.status:
        print("working tree: dirty")
    print()
    if report.findings:
        print("| Severity | Kind | Location | Detail | Matched | Recommendation |")
        print("|---|---|---|---|---|---|")
        for finding in report.findings:
            print(
                f"| {finding.severity} | {finding.kind} | `{finding.location}` | "
                f"{finding.message} | {finding.detail} | {finding.recommendation} |"
            )
    else:
        print("No findings.")
    print()
    print("Checks:")
    for check in report.checks:
        suffix = f" - {check.detail}" if check.detail else ""
        print(f"- {check.status}: {check.label}{suffix}")
    print()
    if added:
        print(
            f"note: {added} new finding(s) recorded in {IGNORE_FILE_NAME} (unchecked). "
            "Mark `[x]` there if you judge it a false positive to exclude it from future runs."
        )
    if removed:
        print(f"note: {removed} resolved finding(s) removed from {IGNORE_FILE_NAME} (no longer detected).")
    if suppressed:
        print(f"suppressed as false positive ({IGNORE_FILE_NAME}): {len(suppressed)}")


def install_global_hook() -> int:
    runner = (TOOL_DIR / "pre-push-check").resolve()
    hooks_dir = TOOL_DIR / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / DEFAULT_HOOK
    hook.write_text(
        "#!/usr/bin/env sh\n"
        f"{HOOK_MARKER}\n"
        "set -eu\n"
        "repo=$(git rev-parse --show-toplevel 2>/dev/null || pwd)\n"
        f"exec {shlex.quote(str(runner))} --repo \"$repo\"\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    proc = run(["git", "config", "--global", "core.hooksPath", str(hooks_dir)], TOOL_DIR)
    if proc.returncode != 0:
        print(proc.stdout, file=sys.stderr)
        return proc.returncode
    print(f"installed global pre-push hook: {hook}")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a push preflight check for one Git repository.")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="repository path; defaults to current directory")
    parser.add_argument("--install-global-hook", action="store_true", help="install this tool as the global pre-push hook")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.install_global_hook:
        return install_global_hook()

    repo = repo_root(args.repo.resolve())
    report = make_report(repo)
    checked_map, added, removed = sync_ignore_file(repo, report.findings)
    suppressed = [f for f in report.findings if checked_map.get(finding_fingerprint(f))]
    report.findings = [f for f in report.findings if not checked_map.get(finding_fingerprint(f))]
    print_report(report, suppressed=suppressed, added=added, removed=removed)
    return 1 if any(f.severity == "Blocker" for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
