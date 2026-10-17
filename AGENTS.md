# AGENTS.md - Linux Natural-Language Terminal Assistant (LNTA)

## Architectural Non-Negotiables
1. **Language & Stack**: Go 1.23+. CLI via `spf13/cobra`. TUI/Output via `charmbracelet/lipgloss` and `charmbracelet/huh` (for interactive approvals). YAML/Frontmatter via `gopkg.in/yaml.v3` and `adrg/frontmatter`. LLM Client via `sashabaranov/go-openai` (configured for OpenAI-compatible endpoints: OpenRouter, Anthropic proxy, Ollama, Gemini).
2. **No Raw Unbounded Bash**: The LLM NEVER gets a raw, unrestricted bash tool. It gets four strictly typed tools:
   - `inspect_system`: Executes strictly inside `bwrap` with `--ro-bind / /`, `--tmpfs /tmp`, and `--tmpfs` masking `~/.ssh`, `~/.gnupg`, `~/.aws`, and `~/.config/lnta`. Stdin is `/dev/null`.
   - `write_scoped_file`: Atomically backs up existing target to `~/.local/share/lnta/snapshots/<run_id>/`, checks that target path matches the active Instruction Pack's `allowed_paths` glob, and writes via temp-file rename.
   - `mutate_system`: Pauses execution, prints the exact command, working directory, and risk rationale via `huh.Confirm`, and only executes upon explicit human approval.
   - `complete_task`: Triggers the harness to execute the active Instruction Pack's `verify_script`. If `verify_script` fails, `complete_task` returns an error to the LLM with the validation output; the agent CANNOT exit with success until verification passes.
3. **Zero Stubs**: Never write `// TODO` or mock implementations. Every phase must compile cleanly (`go build ./...`) and pass unit/integration tests (`go test -v ./...`).
