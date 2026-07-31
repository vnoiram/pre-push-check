# pre-push-check

`pre-push-check` is a local push preflight tool. It checks whether a repository is safe to publish before `git push`.

The default behavior is report-only: it does not format files, amend commits, install dependencies, or push for you. If it finds a blocker, it exits non-zero so a `pre-push` hook can stop the push.

## What It Checks

Always-on checks:

- Push range, branch, upstream, remotes, and working tree status
- Secret-like values in tracked files
- Secret-like changes in the commits being pushed, using `gitleaks` when available and a Git fallback otherwise
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

## Suppressing False Positives

Every run writes `.pre-push-check-ignore.md` at the target repository root and adds it to that
repository's `.gitignore` automatically. This is the one exception to the report-only default:
the tool always maintains this file so persistent false positives don't block `git push` forever.

Each finding is fingerprinted from its `kind` + `location` (`file:line`) + `message`. New findings
are appended to the table as an unchecked row (`[ ]`). Edit the file and change the box to `[x]`
to mark a row as a false positive; on the next run that exact finding is excluded from the report
and no longer counts toward the Blocker verdict.

Because the fingerprint includes the line number, moving code so the line shifts produces a new
fingerprint and the finding reappears (unchecked) rather than staying silently suppressed. This is
intentional: it favors re-review over silently trusting a stale suppression.

Rows for findings that no longer occur (fixed in code, so the same fingerprint is not produced by
the current run) are removed automatically on the next run, keeping the table limited to findings
that are still present. If every row is removed, the file itself is deleted.

Findings with real content point at the specific thing that triggered them — `dirty-worktree` lists
the actual changed paths (e.g. `a.py, b.py`) and a failed `gofmt -l` lists the actual unformatted Go
files — so their location/fingerprint changes whenever the underlying content changes. Checking one
off only suppresses that exact set; a different dirty file or a different unformatted file produces
a new fingerprint and is reported again. `dirty-worktree` is reported as `Note` rather than
`Warning` since it should stay visible every run rather than invite a one-time dismissal.

A few kinds have no specific content to anchor to — a plain yes/no repo-state check, not "these
files are the reason" — and are never written to the table, always reported at full severity
regardless of any past checkbox: `upstream`, `remote`, and `command`. `command` in particular only
carries `` `<label>` failed with exit code N ``, not which assertion or file actually failed, so a
checked-off row would silently swallow a different, unrelated future failure of the same command.

The file is local-only (gitignored) — it records this machine's judgment calls, not a
team-wide policy.

## Requirements

Required:

- Python 3.10 or newer
- Git
- POSIX shell for the `pre-push-check` wrapper

Optional tools are detected at runtime: `gitleaks`, `gh`, Node package managers, `ruff`, `pytest`, Go, Cargo, Java build tools, .NET, Make, CMake, Ruby, PHP, ShellCheck, and PowerShell.

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
