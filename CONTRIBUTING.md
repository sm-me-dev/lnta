# Contributing to LNTA

Thank you for your interest in contributing to the Linux Natural-Language Terminal Assistant (**LNTA**).

LNTA is built for production Linux systems. We maintain strict architectural constraints to ensure that an AI agent can never inadvertently damage a host or leak private credentials.

---

## Table of Contents

- [Architectural Non-Negotiables](#architectural-non-negotiables)
- [Development Setup](#development-setup)
- [Testing & Quality Gates](#testing--quality-gates)
- [How to Add New Linux Distribution Rules](#how-to-add-new-linux-distribution-rules)
- [How to Add an Embedded Instruction Pack](#how-to-add-an-embedded-instruction-pack)
- [Running & Extending the Evaluation Harness (`cmd/lnta-eval`)](#running--extending-the-evaluation-harness-cmdlnta-eval)
- [Pull Request Checklist](#pull-request-checklist)

---

## Architectural Non-Negotiables

Before submitting code, review our non-negotiable architectural invariants:

1. **Language & Stack**: Go 1.23+. CLI via `spf13/cobra`. Terminal UI/Output via `charmbracelet/lipgloss`, `bubbletea`, and `charmbracelet/huh`. YAML/Frontmatter via `gopkg.in/yaml.v3` and `adrg/frontmatter`. LLM Client via `sashabaranov/go-openai`.
2. **Zero Raw Unbounded Bash**: The LLM **NEVER** gets a raw shell execution tool. It interacts with the operating system strictly through four typed tools:
   - `inspect_system`: Executes strictly inside `bwrap` with `--ro-bind / /`, `--tmpfs /tmp`, and `--tmpfs` masking `~/.ssh`, `~/.gnupg`, `~/.aws`, and `~/.config/lnta`. Stdin is `/dev/null`.
   - `write_scoped_file`: Atomically backs up existing target to `~/.local/share/lnta/snapshots/<run_id>/`, checks that target path matches the active Instruction Pack's `allowed_paths` glob, and writes via temp-file rename.
   - `mutate_system`: Evaluated by the **Semantic Blast-Radius Classifier**. Pauses execution, prints the exact command, working directory, and risk rationale, and only executes upon explicit human approval.
   - `complete_task`: Triggers the harness to execute the active Instruction Pack's `verify_cmd`. If `verify_cmd` fails, `complete_task` returns an error to the LLM with the validation output; the agent CANNOT exit with success until verification passes.
3. **Zero Stubs**: Never commit `// TODO` or mock implementations. Every package must compile cleanly (`go build ./...`) and pass tests (`go test -v ./...`).

---

## Development Setup

### Prerequisites
- Linux OS (Ubuntu 22.04+, Debian 12+, Fedora 39+, Arch, or openSUSE)
- Go 1.23 or newer
- Bubblewrap (`bwrap`) installed (`sudo apt install bubblewrap` / `sudo dnf install bubblewrap`)
- Recommended validators: `desktop-file-validate`, `systemd-analyze`, `shellcheck`, `ufw`, `iproute2` (`ss`)

### Building the Project
```bash
git clone https://github.com/sm-me-dev/lnta.git
cd lnta
go build -o bin/lnta ./cmd/lnta
```

Run diagnostics:
```bash
./bin/lnta doctor --verbose
```

---

## Testing & Quality Gates

Run the unit test suite:
```bash
go test -v ./...
```

Run tests with race detection:
```bash
go test -race ./...
```

Validate all embedded instruction packs:
```bash
go run ./cmd/lnta packs validate packs/ --strict
```

---

## How to Add New Linux Distribution Rules

System fingerprinting is managed in `internal/fingerprint/`.

1. **Fingerprint Probing** (`internal/fingerprint/fingerprint.go`):
   - Reads `/etc/os-release` to extract `ID`, `VERSION_ID`, `ID_LIKE`.
   - Detects package managers (`apt`, `dnf`, `pacman`, `zypper`, `apk`).
   - Detects init system (systemd, OpenRC, runit).
   - Detects desktop environment (`XDG_CURRENT_DESKTOP`, `WAYLAND_DISPLAY`).
2. **Adding Distribution Tests**:
   - Add test fixtures or mocks to `internal/fingerprint/fingerprint_test.go`.
   - Verify that non-systemd or unusual distributions degrade gracefully without panicking.

---

## How to Add an Embedded Instruction Pack

Embedded packs are compiled directly into the `lnta` binary via Go's `embed` package.

1. **Create the Pack File**:
   Add a new Markdown file under `packs/<pack-id>.md`.
2. **Define Frontmatter**:
   ```yaml
   ---
   id: my-new-pack
   name: My New Pack
   triggers:
     - keyword
     - multi word phrase
   allowed_paths:
     - "~/.config/myapp/*.conf"
   required_bins:
     - myapp
   context_cmd: myapp --version
   verify_cmd: myapp check "${target}"
   ---
   # My New Pack
   Runbook guidance...
   ```
3. **Validate the Pack**:
   ```bash
   go run ./cmd/lnta packs validate packs/my-new-pack.md --strict
   ```
4. **Compile & Verify Embedding**:
   Embedded packs are automatically included via `embedded_packs.go`:
   ```bash
   go build -o bin/lnta ./cmd/lnta
   ./bin/lnta packs list | grep my-new-pack
   ```

---

## Running & Extending the Evaluation Harness (`cmd/lnta-eval`)

The automated evaluation harness benchmarks LNTA's agent orchestrator against deterministic scenarios using a canned mock LLM (no network egress or API keys required).

### Running Evaluations
```bash
go run ./cmd/lnta-eval
```

Output metrics:
- **Completion Rate**: Intended task outcome achieved.
- **Harness Verification Rate**: Verification gate verdicts were objectively correct.
- **Unsafe-Action Block Rate**: Out-of-scope writes or forbidden mutations were blocked.
- **Pre-flight Latency**: Fingerprint + pack routing duration.

### Core Benchmark Scenarios
1. `valid-desktop`: Creates a valid `.desktop` file; expects verified completion.
2. `missing-executable`: Targets a non-existent binary; expects verification failure.
3. `block-etc-hosts`: Attempts unauthorized write to `/etc/hosts`; expects `SCOPE_VIOLATION`.
4. `recover-malformed`: Introduces invalid syntax and expects auto-recovery loop to succeed.
5. `explain-mode`: Tests `--explain` mode to verify write tools are absent from declarations.
6. `dry-run`: Tests `--dry-run` to verify diff previews without disk modification.

### Adding an Evaluation Scenario
To add a new benchmark scenario:
1. Open `cmd/lnta-eval/main.go`.
2. Implement a new scenario function matching `scenarioFn`:
   ```go
   func scenarioCustom(tmpDir string) (
       responses [][]openai.ChatCompletionStreamResponse,
       verified bool,
       unsafe bool,
       dryRunPrev bool,
       check func(result string) bool,
   ) { ... }
   ```
3. Register the scenario in `main()`.
4. Verify all scenarios pass with 100% verification and block rates.

---

## Pull Request Checklist

Before opening a pull request, ensure:
- [ ] Code compiles cleanly: `go build ./...`
- [ ] All unit and integration tests pass: `go test -v ./...`
- [ ] All instruction packs pass strict validation: `go run ./cmd/lnta packs validate packs/ --strict`
- [ ] Evaluation harness passes: `go run ./cmd/lnta-eval`
- [ ] No stubs or unconstrained bash tools were introduced.
- [ ] Documentation updated in `docs/` if modifying flags, packs, or security boundaries.
