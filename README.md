# AI Security Checker

AI Security Checker runs local, repeatable security checks against AI agent source, selected model files and the current Linux runtime. It organises evidence into five layers and keeps unknown or failed checks visible.

The checker uses one upstream scanner, [MEDUSA](https://github.com/Pantheon-Security/medusa), pinned as a Git submodule. The wrapper adds bounded GGUF metadata parsing, local listener and container inspection, report comparison, cancellation and a loopback-only web interface.

This tool supports security decisions. It cannot prove that model weights have no hidden trigger or that a host has no route from the public internet.

## Safety rules

- Scans are read-only for target repositories and services.
- The checker never runs target code, renders a scanned template or deserialises a model file.
- MEDUSA runs without a shell and receives a reduced environment. Its cache stays under `.state/`.
- Reports use private directory and file modes. Git ignores reports, local configuration, virtual environments, model files, environment files and common private-key formats.
- A wildcard listener or container port produces an exposure-uncertain finding. It does not prove public exposure.
- An audit produces proposed repair tasks but never applies them.
- The CLI and web process refuse to run as root.

## Install

Requirements are Linux, Python 3.11 or later, Git and the local commands needed for the checks you want, such as `ss`, Docker and systemd.

```bash
git clone --recurse-submodules https://github.com/froodx/ai-security-checker.git
cd ai-security-checker
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -r requirements-dev.txt
```

The MEDUSA tag is pinned by the submodule commit. Do not install MEDUSA from a floating branch.

## Configure targets

The built-in `hermes` target resolves below `$HOME/code`. For other paths, either repeat `--path` on the CLI or copy the example configuration:

```bash
cp config/targets.example.yaml config/targets.yaml
```

`config/targets.yaml` is local and ignored by Git. Every selected path must resolve below one of its `allowed_roots`. The web interface accepts no more than five code paths for one run.

Do not add a large model directory until you intend to inspect it. Model paths require an explicit `--model-path` or local target configuration entry.

## Run scans

```bash
./ai-security-check scan --target hermes --mode basic
./ai-security-check scan --target hermes --mode medium
./ai-security-check scan --path "$HOME/code/project-one" --path "$HOME/code/project-two" --mode medium
./ai-security-check scan --path "$HOME/code/project" --model-path "$HOME/models/approved-model" --mode medium
```

Basic mode uses MEDUSA quick mode only after a completed comparable baseline exists. The first Basic run performs a full static scan. Medium mode performs full static and local checks. Full mode adds a deeper report contract, but it does not run behavioural prompts without a separate approval and disposable target.

Resource limits are conservative. MEDUSA receives two workers and a mode-specific time limit. The startup example adds a 15-minute outer limit. The GGUF reader stops before tensor data, limits metadata to 32 MiB and limits any string to 1 MiB. Files larger than 64 MiB are inventoried but not hashed by default.

## Use the local web interface

```bash
./ai-security-check web --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765`. The interface has a target selector, explicit path fields, mode selection, live status, timestamped logs, report links and a Cancel button. It rejects non-loopback binding, paths outside configured roots and overlapping scans.

Cancellation sends `SIGTERM` to the MEDUSA process group and uses `SIGKILL` after a bounded grace period. Partial reports remain available and all coverage rows are marked cancelled.

## Read reports

Each run creates a private directory below `reports/` with these main files:

- `summary.md` contains finding totals, priorities, prior-run changes and blind spots.
- `five-layer-report.md` records evidence and limitations for all five layers.
- `findings.json` contains stable canonical finding records.
- `coverage.json` records passed, finding, not checked, unknown, error, cancelled or not applicable states.
- `fix-prompts.md` contains approval-gated repair options and copyable agent tasks.
- `scan-log.txt`, `runtime.json`, `model-inventory.json`, `manifest.json` and `medusa/` retain redacted evidence and scanner provenance.

The latest run name is stored in `reports/latest.txt`. Reports are ignored by Git. Do not copy them into an issue or public repository without a separate review.

## Repair workflow

Read `fix-prompts.md`, select one option and approve that finding only. Hand the matching task to Claude Code or Codex after approval. The task requires a proposed diff, tests, verification and rollback instructions. Restarts, deployment changes, firewall edits, network changes and credential rotation need a separate approval.

Run the checker again after a repair. Stable finding IDs allow the next report to classify findings as new, unchanged or resolved.

## Upstream updates

Check for tags without changing the submodule:

```bash
./ai-security-check upstream-check
```

An update requires an exact tag and an approval flag:

```bash
scripts/update-upstream.sh --tag vYYYY.N.N --approve
```

The script verifies the tag with the local Git trust store. An unsigned or locally unverifiable tag also requires `--allow-unsigned`. It records the prior commit, installs the selected checkout without changing dependencies, runs smoke tests and restores the prior commit after a failure. Review the submodule diff and full test suite before committing an update.

## Scheduling

`scripts/startup-check-example.sh` starts a locked, bounded Basic scan in the background. It does not modify or restart the target.

The files under `examples/systemd/` define a monthly user timer. Review the paths, copy them to `~/.config/systemd/user/`, then enable the timer only if you want scheduled runs. The repository does not install or enable it.

## Tests

```bash
.venv/bin/python -m pytest
```

The tests cover GGUF bounds, template warnings, redaction, path allowlists, MEDUSA result conversion, listener and Compose exposure, report states, missing tools, cancellation, multiple targets and the web API.

## Known limits

- The checker does not query a live CVE database. Runner advisory coverage remains unknown until an exact version receives a current review.
- Model digests identify bytes but do not prove that a publisher or reference is trustworthy.
- Static template checks can miss trigger-dependent instructions and runtime overrides.
- Local firewall access does not reveal every router, NAT or upstream network rule.
- MEDUSA optional linters may be absent. The report lists each missing tool and does not treat incomplete coverage as a pass.
- Full mode does not run exploit payloads or test a production agent's behaviour.

## Licence

The wrapper is licensed under AGPL-3.0-or-later. MEDUSA remains an independent AGPL-3.0-or-later project in the `medusa/` submodule with its own notices and history.
