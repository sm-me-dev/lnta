// Package audit implements structured JSONL audit logging with automatic
// redaction of secrets (bearer tokens, sk-... keys, private keys, password
// assignments).
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Entry is a single audit log record written as one JSON line.
type Entry struct {
	Ts      string            `json:"ts"`
	Level   string            `json:"level,omitempty"`
	Event   string            `json:"event"`
	RunID   string            `json:"run_id,omitempty"`
	Message string            `json:"message,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// redaction pairs each secret-matching regex with its replacement text.
type redaction struct {
	re      *regexp.Regexp
	repl    string
	maskVal bool // if true, keep the matched key prefix and mask only the value
}

var redactors = []redaction{
	// Bearer tokens: Authorization: Bearer <token> (optionally with the
	// "authorization:" prefix so the assignment redactor below does not
	// double-match the leftover "Bearer" word as a value).
	{regexp.MustCompile(`(?i)(authorization[ \t]*:[ \t]*)?bearer[ \t]+[A-Za-z0-9._\-+/=]{8,}`),
		"${1}Bearer [REDACTED]", false},
	// sk-... API keys (OpenAI/Anthropic-style, may contain hyphens)
	{regexp.MustCompile(`sk-[A-Za-z0-9_\-]{16,}`), "[REDACTED]", false},
	// PEM private key blocks
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
		"[REDACTED PRIVATE KEY BLOCK]", false},
	// Password / secret / token assignments: password=value, api_key="value", etc.
	// ("authorization" is handled by the bearer redactor above.)
	{regexp.MustCompile(`(?i)(\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b)[ \t]*[:=][ \t]*["']?([^"';\s]{3,})`),
		"$1=[REDACTED]", true},
}

// Logger appends structured JSONL entries to a log file.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	path string
}

var (
	defaultOnce   sync.Once
	defaultLogger *Logger
	defaultErr    error
)

// homeDir returns the user's home directory.
func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if u, err := os.UserHomeDir(); err == nil {
		return u
	}
	return ""
}

// dataRoot returns ~/.local/share/lnta.
func dataRoot() string {
	return filepath.Join(homeDir(), ".local", "share", "lnta")
}

// DefaultLogger returns the process-wide audit logger writing to
// ~/.local/share/lnta/logs/audit.jsonl, lazily initialized. Best-effort: if
// the log file cannot be opened, a nil logger is returned and Log calls are
// silently dropped.
func DefaultLogger() *Logger {
	defaultOnce.Do(func() {
		defaultLogger, defaultErr = NewLogger("")
	})
	return defaultLogger
}

// NewLogger creates a logger writing to <dir>/logs/audit.jsonl. If dir is
// empty the default data root is used. The directory and file are created as
// needed (mode 0o700 / 0o600).
func NewLogger(dir string) (*Logger, error) {
	root := dir
	if root == "" {
		root = dataRoot()
	}
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(logDir, "audit.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f, path: path}, nil
}

// Close releases the underlying log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Log appends a single audit entry. It is safe for concurrent use.
func (l *Logger) Log(event, message string, details map[string]string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	e := Entry{
		Ts:      time.Now().UTC().Format(time.RFC3339Nano),
		Level:   "info",
		Event:   event,
		Message: redactString(message),
		Details: redactMap(details),
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, werr := l.file.Write(b)
	return werr
}

// Log is a package-level helper that writes to the default logger. Errors are
// ignored so audit logging never blocks the calling operation.
func Log(event, message string, details map[string]string) {
	l := DefaultLogger()
	if l != nil {
		_ = l.Log(event, message, details)
	}
}

// redactString applies all secret redactions to s.
func redactString(s string) string {
	for _, r := range redactors {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// redactMap redacts every value in the map.
func redactMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = redactString(v)
	}
	return out
}

// sanity check: ensure fmt and strings are used.
var _ = fmt.Sprintf
var _ = strings.Contains
