# AGENTS.md - Linux Natural-Language Terminal Assistant (LNTA)

## Architectural Non-Negotiables
1. **Language & Stack**: Go 1.27.2+. CLI via `spf13/cobra`. TUI/Output via `charmbracelet/lipgloss` and `charmbracelet/huh` (for interactive approvals). YAML/Frontmatter via `gopkg.in/yaml.v3` and `adrg/frontmatter`. LLM Client via `sashabaranov/go-openai` (configured for OpenAI-compatible endpoints: OpenRouter, Anthropic proxy, Ollama, Gemini).
2. **No Raw Unbounded Bash**: The LLM NEVER gets a raw, unrestricted bash tool. It gets four strictly typed tools:
   - `inspect_system`: Executes strictly inside `bwrap` with `--ro-bind / /`, `--tmpfs /tmp`, and `--tmpfs` masking `~/.ssh`, `~/.gnupg`, `~/.aws`, and `~/.config/lnta`. Stdin is `/dev/null`.
   - `write_scoped_file`: Atomically backs up existing target to `~/.local/share/lnta/snapshots/<run_id>/`, checks that target path matches the active Instruction Pack's `allowed_paths` glob, and writes via temp-file rename.
   - `mutate_system`: Pauses execution, prints the exact command, working directory, and risk rationale via `huh.Confirm`, and only executes upon explicit human approval.
   - `complete_task`: Triggers the harness to execute the active Instruction Pack's `verify_script`. If `verify_script` fails, `complete_task` returns an error to the LLM with the validation output; the agent CANNOT exit with success until verification passes.
3. **Zero Stubs**: Never write `// TODO` or mock implementations. Every phase must compile cleanly (`go build ./...`) and pass unit/integration tests (`go test -v ./...`).

## Versioning and Releases

- Use Semantic Versioning. Increment PATCH for compatible fixes, security hardening, and reliability work; MINOR for backward-compatible features; MAJOR for breaking behavior. Choose from the highest existing `vMAJOR.MINOR.PATCH` tag and do not reuse a tag.
- Keep the fallback version in `version.go`, `Formula/lnta.rb`, the pinned download filenames in `README.md`, the default in `scripts/apt/generate-index.sh`, and the top `CHANGELOG.md` release entry aligned. GoReleaser stamps published binaries from the release tag.
- Add dated user-facing release notes to `CHANGELOG.md`. The annotated tag message supplies GitHub release notes (`--notes-from-tag`), so keep its text aligned with the changelog entry.
- Before tagging, run `go test ./...`, `go vet ./...`, `go build ./...`, the configured lint checks, and `goreleaser check` when GoReleaser is available.
- Commit and push the release metadata, then create an annotated `vX.Y.Z` tag on that commit with notes matching the changelog entry. Run `goreleaser release --snapshot --clean --skip=sign,publish` locally after creating the tag; use a disposable distribution directory because `--clean` removes it. Push the tag only after the snapshot artifacts are verified and the release is ready: `.github/workflows/release.yml` builds and signs artifacts, publishes the GitHub release and APT repository, and updates `gh-pages`.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
