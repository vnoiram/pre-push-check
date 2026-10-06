# pre-push-check

`pre-push-check` is a local push preflight tool. It checks whether a repository is safe to publish before `git push`.

The default behavior is report-only: it does not format files, amend commits, install dependencies, or push for you. If it finds a blocker, it exits non-zero so a `pre-push` hook can stop the push.

## What It Checks

Always-on checks:

- Push range, branch, upstream, remotes, and working tree status
- Secret-like values in tracked files
- Secret-like changes in the commits being pushed, using `gitleaks` when available and a Git fallback otherwise
  (`gitleaks` findings are rerun with `-v`, expanded into suppressible findings, and listed in `.pre-push-check-ignore.md`)
- Commit author emails, WIP/fixup/squash subjects, and merge commits in the push range
- Conflict markers
- Clear debug remnants such as `console.log`, `debugger`, `fmt.Println`, `Write-Host`, `dbg!`, and `var_dump`
- Local absolute paths such as Unix, macOS, and Windows home-directory paths
- Generated, temporary, cache, and large tracked files
- `.env` files and common `.gitignore` coverage gaps
- GitHub Actions workflow risks such as `pull_request_target`, tag-pinned third-party actions, and secret echoing
- Safe CI-declared commands from workflow `run:` lines, such as `npm run lint`, `pytest`, `go test ./...`, `cargo test`, and `make test`
- Recent GitHub Actions runs when `gh` is available and authenticated

Stack-specific checks are run only when the repository declares the matching stack and the required tool is installed:

- Make/just: declared `lint`, `typecheck`, `check`, `build`, and `test` targets or recipes
- Node.js/npm/pnpm/yarn/bun: declared `lint`, `typecheck`, `check`, `build`, and `test` scripts, plus lockfile presence
- Python: `ruff format --check .`, `ruff check .`, `pytest`
- Go: `gofmt -l`, `go vet ./...`, `go test ./...`
- Rust: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`
- Java/JVM: Gradle or Maven wrapper first, then installed `gradle` or `mvn`
- .NET: `dotnet build -warnaserror`, `dotnet test`
- C/C++: declared Makefile targets and configured CMake build directories
- Ruby: `ruby -c` and optional `bundle exec rspec`
- PHP: `php -l` and `composer validate --strict`
- Shell: `bash -n` and optional `shellcheck`
- PowerShell: parser validation with `pwsh` or `powershell`

Skipped checks are listed with the reason. Missing tools are not installed automatically.

## Timing Output

While checks are running, progress is written to stderr so long repositories do not appear stuck:

```text
pre-push-check: start scan tracked file contents
pre-push-check: done scan tracked file contents (1.7s)
pre-push-check: start command: pytest
pre-push-check: done command: pytest (42.3s)
```

The final `Checks:` section also includes elapsed time for measured phases and external commands,
making it easier to identify whether file scans, history inspection, CI adoption, or stack-specific
commands are responsible for slow runs.

If the repository state is unchanged since the previous run, checks that passed cleanly are reused
from a local cache block in `.pre-push-check-ignore.md` and shown as `cached-pass`. The cache key
includes `HEAD`, the upstream revision, working tree status, and the full `git diff HEAD --binary`,
so editing code or changing the push range invalidates the cache. Failed commands and scans that
produced findings are not treated as clean passes. The file is written under a repo-local lock, so
running checks in multiple repositories at the same time does not share or corrupt cache state.

## Suppressing False Positives

Every run writes `.pre-push-check-ignore.md` at the target repository root and adds it to that
repository's `.gitignore` automatically. This is the one exception to the report-only default:
the tool always maintains this file so persistent false positives and previous clean-pass cache
state don't block `git push` forever.

Each finding is fingerprinted from its `kind` + `message` + the actual matched content (e.g. the
literal source line a secret/debug/local-path regex matched). The location is deliberately *not*
part of the fingerprint when there is matched content; for findings without content, only the file
(not the line number) is used. The table
records that matched content too, so a row reads like:

```
| [ ] | f8d29dc8cdf8 | Blocker | secret | foobar.yaml:1 | Possible secret in tracked file. | redacted sample credential |
```

The file has three sections: unchecked "pending" tables for findings still awaiting a decision
(`blocker` first, then `other`), a checked "ignored as false positive" table for rows you have
already dismissed, and an internal cache block for previous clean-pass results. New findings are
appended as unchecked rows (`[ ]`) under the relevant pending subsection. Edit the file and change
the box to `[x]` to mark a row as a false positive; on the next run that row moves down into the
ignored table, that exact finding is excluded from the report, and it no longer counts toward the
Blocker verdict.

Because the fingerprint is based on the matched content rather than its position, moving code so
the line shifts does not make a checked-off finding reappear. Editing the matched line to a
different value still produces a new fingerprint and the finding comes back unchecked.

Findings with the same fingerprint are merged into a single row/report entry whose location lists
every occurrence (`[x3] a.rb:1,9; b.rb:3`, grouped per file; every file name is always shown, only line numbers beyond 10 per file are elided). Checking that one row
suppresses all identical occurrences, including ones added later in other files.

The matched part of the line is wrapped in Markdown bold (`**...**`) in both the report and the
ignore file, e.g. `test_it(**csrf_token = param.token** || ...)`. This is display-only and does not
affect the fingerprint.

Rows for findings that no longer occur (fixed in code, so the same fingerprint is not produced by
the current run) are removed automatically on the next run, keeping the table limited to findings
that are still present. If every row is removed, the file itself is deleted.

Findings with real content point at the specific thing that triggered them — `dirty-worktree` lists
the actual changed paths (e.g. `a.py, b.py`) and a failed `gofmt -l` lists the actual unformatted Go
files — so their fingerprint changes whenever the underlying content changes. Checking one
off only suppresses that exact set; a different dirty file or a different unformatted file produces
a new fingerprint and is reported again. `dirty-worktree` is reported as `Note` rather than
`Warning` since it should stay visible every run rather than invite a one-time dismissal.

A few kinds have no specific content to anchor to — a plain yes/no repo-state check, not "these
files are the reason" — and are never written to the table, always reported at full severity
regardless of any past checkbox: `upstream`, `remote`, and `command`. `command` in particular only
carries `` `<label>` failed with exit code N ``, not which assertion or file actually failed, so a
checked-off row would silently swallow a different, unrelated future failure of the same command.
`gitleaks` detections are an exception to that command shape: when `gitleaks` reports leaks,
pre-push-check converts each leak into a `secret-history` finding with file, line, rule, and
fingerprint information, so intentional fixtures such as test JWTs can be checked off just like
other false positives.

Future checks should follow the same split. If a check detects content that may intentionally stay
in the repository, such as test credentials, fixture-like debug lines, local-path examples, or
versioned generated files, emit a concrete `Finding` with stable location and matched content so it
can be reviewed and suppressed. If a check is an ordinary quality gate whose failure should disappear
after fixing code, such as formatting, lint, syntax, build, or test failures, keep it as a command
check and put the useful details in the `Checks:` output instead of creating persistent findings.
`ruff` is the model for that command-check behavior.

The file is local-only (gitignored) — it records this machine's judgment calls, not a
team-wide policy.

## Requirements

Required:

- Python 3.10 or newer
- Git
- POSIX shell for the `pre-push-check` wrapper

Optional tools are detected at runtime: `gitleaks`, `gh`, Node package managers, `ruff`, `pytest`, Go, Cargo, Java build tools, .NET, Make, CMake, Ruby, PHP, ShellCheck, and PowerShell. For `pytest`, a repository-local `.venv` or `venv` is used before the system command when available.

The Python implementation uses only the standard library.

## Usage

Run in the current repository:

```sh
./pre-push-check
```

Run against a specific repository:

```sh
./pre-push-check --repo /path/to/repo
```

Install as the global `pre-push` hook for the current Git user:

```sh
./pre-push-check --install-global-hook
```

This creates a local `hooks/pre-push` file and configures Git with:

```sh
git config --global core.hooksPath /path/to/pre-push-check/hooks
```

The generated `hooks/` directory is intentionally ignored because it contains an installation-specific absolute path.

## Git Repository Setup

Suggested repository name:

```text
pre-push-check
```

Initial setup:

```sh
git init
git add .
git commit -m "feat: add pre-push check tool"
```

## Exit Codes

- `0`: no blocker found
- `1`: at least one blocker found, or the path is not a Git repository

Warnings and notes are reported but do not block by themselves.
