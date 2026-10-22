# Implementation plan

## Confirmed local state

- The host is Linux on x86-64 with Python 3.12.3.
- Docker 29.8.2 is available through the current user's socket. The systemd user manager reports a degraded state, so service checks must record individual command failures.
- The supplied source target and focus directory exist below `$HOME/code`.
- The supplied target Git worktree already contains unrelated untracked files. The checker and this build must not alter them.
- MEDUSA tag `v2026.7.0` resolves to commit `5f217edf8b09b960a32311982754dd2717a70c9b`. The tag is annotated but has no cryptographic signature. The version and commit are pinned as a Git submodule.
- The installed `medusa scan --help` output confirms `--quick`, `--force`, `--no-cache`, `--fail-on`, `--output` and JSON, HTML, Markdown and combined report formats.

## Design

`ai-security-check` will call a small Python package. The orchestrator will validate all target paths against configured roots, create a private report directory, run MEDUSA without a shell, run local read-only probes, merge canonical findings and write every report even after an error or cancellation.

MEDUSA will run from the pinned virtual environment. Its `HOME` will point at `.state/medusa-home`, which keeps its cache out of scanned repositories and the user's normal home directory. A Basic scan may use `--quick` only after a completed comparable scan. Medium and Full scans will use `--force`. Full mode will report behavioural tests as not checked unless the caller supplies separate approval and a disposable fixture. Version 1 will not send evidence to an AI provider.

The runtime probe will use argument arrays for `ss`, Docker, systemd and version commands. It will redact credential-shaped text before it writes logs or evidence. It will treat wildcard listeners as uncertain exposure unless firewall or network evidence confirms more.

The GGUF reader will parse only bounded metadata. It will reject oversized strings, arrays, nesting and malformed offsets before it reaches tensor data. It will hash extracted chat-template text without rendering it.

The Flask UI will bind only to `127.0.0.1`, reject root execution and accept at most five paths below the allowlisted roots. One worker thread will own the current scan. Cancellation will set a shared event and terminate the active MEDUSA process group before reports are finalised with cancelled coverage.

## Repository safety

Generated reports, checker state, local target configuration, virtual environments, private keys, environment files and common model formats are ignored. Before publication, the complete index and commit history will be checked for credential patterns, private host configuration and large files. Only reviewed files will be pushed to the public repository.

## Build order

1. Add package metadata, configuration examples and the executable CLI.
2. Implement path validation, MEDUSA execution, cancellation and raw evidence capture.
3. Implement runtime and GGUF probes, canonical findings, coverage and previous-run comparison.
4. Add Markdown and JSON reports, the local UI and the agent skill.
5. Add upstream checks, the approval-gated update path and scheduling examples.
6. Test fixtures, cancellation, redaction, missing tools, malformed GGUF, network binds and multiple targets.
7. Run a Medium Hermes scan, compare its Git state with the recorded state and inspect generated evidence for secrets.
8. Audit the Git index and history, then create and push the public GitHub repository.

## Acceptance tests

- Run the Python test suite in the pinned virtual environment.
- Scan a synthetic repository with seeded findings and confirm all five coverage rows and report files exist.
- Confirm wildcard IPv4 and IPv6 binds produce an exposure-uncertain finding while loopback binds do not.
- Parse a small GGUF chat template and reject malformed or oversized metadata.
- Start the UI on loopback, poll its status, cancel a slow fixture scan and confirm the run ends as cancelled.
- Run a Medium scan against the supplied local target and compare `git status --short` and `HEAD` before and after.
- Run upstream check and update rollback tests against a disposable clone.
- Scan the public Git index and all local commits for secrets and oversized files before the first push.
