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
