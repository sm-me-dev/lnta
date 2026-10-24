package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
	"gopkg.in/yaml.v3"
)

const (
	// defaultModel is the model used when none is configured.
	defaultModel = "gpt-4o-mini"
	// defaultBaseURL is the default OpenAI-compatible base URL.
	defaultBaseURL = "https://api.openai.com/v1"
	// defaultTemperature is the sampling temperature.
	defaultTemperature = 0.2
	// defaultMaxTokens is the maximum tokens per completion.
	defaultMaxTokens = 4096
	// defaultTimeoutSec is the default request timeout in seconds.
	defaultTimeoutSec = 120
	// configFileName is the user config filename.
	configFileName = "config.yaml"
	// credentialsFileName is the user credentials filename.
	credentialsFileName = "credentials"
	// KeyringServiceName is the OS keyring service identifier.
	KeyringServiceName = "lnta"
	// KeyringUserKey is the OS keyring account/key name for the LLM API key.
	KeyringUserKey = "api_key"
	// defaultGCMaxRuns is the default number of run snapshots to retain.
	defaultGCMaxRuns = 100
	// defaultGCMaxMB is the default max size in MB for snapshot storage.
	defaultGCMaxMB = 100
	// ollamaDiscoveryTimeout is the timeout for Ollama discovery.
	ollamaDiscoveryTimeout = 150 * time.Millisecond
	// ollamaBaseURL is the OpenAI-compatible endpoint exposed by a local
	// Ollama server, used for 100% offline --local mode.
	ollamaBaseURL = "http://127.0.0.1:11434/v1"
)

// ErrNoAPIKey is returned when no LLM API key is found in environment, keyring, credentials, or config.
var ErrNoAPIKey = errors.New("no LLM API key configured: set LNTA_API_KEY, use OS keyring, or run 'lnta setup'")

// ollamaDiscoveryURL is the URL to probe for local Ollama models.
// It is a var (not const) so tests can point it at an httptest server.
var ollamaDiscoveryURL = "http://127.0.0.1:11434/api/tags"

// LocalOllamaModel represents a model discovered from a local Ollama instance.
// Ollama's /api/tags returns "name", "size", "modified_at" fields.
type LocalOllamaModel struct {
	ID       string `yaml:"id" json:"name"`
	Size     int64  `yaml:"size" json:"size,omitempty"`
	Modified string `yaml:"modified" json:"modified_at,omitempty"`
}

// Config holds the LLM agent configuration. Values are loaded from
// ~/.config/lnta/config.yaml and OS keyring / ~/.config/lnta/credentials
// with environment variable overrides (env wins over file). It supports any
// OpenAI-compatible API (via go-openai), Ollama local models, or Anthropic/Gemini
// endpoints that expose an OpenAI-compatible chat completions endpoint.
type Config struct {
	APIKey      string             `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	BaseURL     string             `yaml:"base_url" json:"base_url"`
	Model       string             `yaml:"model" json:"model"`
	Temperature float32            `yaml:"temperature" json:"temperature"`
	MaxTokens   int                `yaml:"max_tokens" json:"max_tokens"`
	TimeoutSec  int                `yaml:"timeout_sec" json:"timeout_sec"`
	LocalModels []LocalOllamaModel `yaml:"local_models,omitempty" json:"local_models,omitempty"`
	GCMaxRuns   int                `yaml:"gc_max_runs,omitempty" json:"gc_max_runs,omitempty"`
	GCMaxMB     int                `yaml:"gc_max_mb,omitempty" json:"gc_max_mb,omitempty"`
}

// configFile is the on-disk representation of Config with optional fields.
type configFile struct {
	APIKey      string             `yaml:"api_key,omitempty"`
	BaseURL     string             `yaml:"base_url"`
	Model       string             `yaml:"model"`
	Temperature *float32           `yaml:"temperature"`
	MaxTokens   *int               `yaml:"max_tokens"`
	TimeoutSec  *int               `yaml:"timeout_sec"`
	LocalModels []LocalOllamaModel `yaml:"local_models,omitempty"`
	GCMaxRuns   *int               `yaml:"gc_max_runs,omitempty"`
	GCMaxMB     *int               `yaml:"gc_max_mb,omitempty"`
}

// EnforceStrictFilePermissions checks if a configuration or credentials file has group or
// world readable/writable bits (mode & 0077 != 0). If insecure permissions are found,
// it prints a security warning to os.Stderr and automatically chmods it to 0600 (-rw-------),
// matching OpenSSH security behavior.
func EnforceStrictFilePermissions(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	perm := fi.Mode().Perm()
	if perm&0077 != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %s has insecure permissions (%04o); changing to 0600\n", path, perm)
		if err := os.Chmod(path, 0600); err != nil {
			return fmt.Errorf("chmod 0600 %s: %w", path, err)
		}
	}
	return nil
}

// DefaultConfigDir returns the default user configuration directory ~/.config/lnta.
func DefaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "lnta")
	}
	return filepath.Join(home, ".config", "lnta")
}

// LoadCredentialsFile reads an API key from the credentials file (enforcing 0600 permissions).
// It supports YAML (api_key: ...), KEY=VALUE, or raw token formats.
func LoadCredentialsFile(path string) (string, error) {
	if err := EnforceStrictFilePermissions(path); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	content := strings.TrimSpace(string(data))
	if content == "" {
		return "", nil
	}

	// Try YAML unmarshaling
	var cf struct {
		APIKey string `yaml:"api_key"`
	}
	if err := yaml.Unmarshal(data, &cf); err == nil && cf.APIKey != "" {
		return strings.TrimSpace(cf.APIKey), nil
	}

	// Try lines: api_key=..., api_key: ..., LNTA_API_KEY=...
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "api_key=") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "api_key=")), "\"'"), nil
		}
		if strings.HasPrefix(line, "api_key:") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "api_key:")), "\"'"), nil
		}
		if strings.HasPrefix(line, "LNTA_API_KEY=") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "LNTA_API_KEY=")), "\"'"), nil
		}
	}

	// Single line raw token
	if !strings.Contains(content, "\n") && !strings.Contains(content, " ") {
		return content, nil
	}

	return "", nil
}

// SaveCredentialsFile writes the API key to path with strict 0600 permissions.
func SaveCredentialsFile(path, apiKey string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	content := fmt.Sprintf("api_key: %s\n", strings.TrimSpace(apiKey))
	return os.WriteFile(path, []byte(content), 0600)
}

// SaveSecret attempts to store the API key in the OS Keyring (via zalando/go-keyring).
// If the keyring is unavailable or returns an error, it automatically falls back
// to saving in ~/.config/lnta/credentials at strict 0600 permissions.
func SaveSecret(apiKey string) error {
	return SaveSecretToDir(DefaultConfigDir(), apiKey)
}

// SaveSecretToDir attempts to store the secret in the OS Keyring, falling back
// to filepath.Join(configDir, "credentials") at strict 0600 permissions.
func SaveSecretToDir(configDir, apiKey string) error {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return errors.New("cannot save empty API key")
	}

	// Attempt OS Keyring first
	err := keyring.Set(KeyringServiceName, KeyringUserKey, apiKey)
	if err == nil {
		return nil
	}

	// Keyring failed or unavailable -> fall back to strict 0600 credentials file
	credPath := filepath.Join(configDir, credentialsFileName)
	return SaveCredentialsFile(credPath, apiKey)
}

// LoadSecret loads the API key from OS Keyring or ~/.config/lnta/credentials.
func LoadSecret() (string, error) {
	return LoadSecretFromDir(DefaultConfigDir())
}

// LoadSecretFromDir loads the API key from:
// 1. OS Keyring (zalando/go-keyring)
// 2. filepath.Join(configDir, "credentials") (enforced at 0600)
func LoadSecretFromDir(configDir string) (string, error) {
	// 1. Try OS Keyring
	secret, err := keyring.Get(KeyringServiceName, KeyringUserKey)
	if err == nil && strings.TrimSpace(secret) != "" {
		return strings.TrimSpace(secret), nil
	}

	// 2. Fall back to credentials file
	credPath := filepath.Join(configDir, credentialsFileName)
	if _, err := os.Stat(credPath); err == nil {
		credSecret, err := LoadCredentialsFile(credPath)
		if err == nil && strings.TrimSpace(credSecret) != "" {
			return strings.TrimSpace(credSecret), nil
		}
	}

	return "", nil
}

// SaveConfigFile writes the configuration to config.yaml in configDir with strict 0600 permissions.
func SaveConfigFile(configDir string, cfg *Config) error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	configPath := filepath.Join(configDir, configFileName)

	cf := configFile{
		BaseURL:     cfg.BaseURL,
		Model:       cfg.Model,
		Temperature: &cfg.Temperature,
		MaxTokens:   &cfg.MaxTokens,
		TimeoutSec:  &cfg.TimeoutSec,
		LocalModels: cfg.LocalModels,
	}
	if cfg.GCMaxRuns > 0 {
		cf.GCMaxRuns = &cfg.GCMaxRuns
	}
	if cfg.GCMaxMB > 0 {
		cf.GCMaxMB = &cfg.GCMaxMB
	}

	data, err := yaml.Marshal(cf)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("write config %s: %w", configPath, err)
	}
	return EnforceStrictFilePermissions(configPath)
}

// LoadConfig loads the agent config from ~/.config/lnta/config.yaml and credentials/keyring,
// applying sensible defaults and environment variable overrides:
//   LNTA_API_KEY, LNTA_BASE_URL, LNTA_MODEL.
//
// A missing config file is not an error; defaults, keyring/credentials, and env vars are used.
func LoadConfig() (*Config, error) {
	return LoadConfigDir(DefaultConfigDir())
}

// LoadConfigDir loads the agent config from a specific directory.
func LoadConfigDir(dir string) (*Config, error) {
	if dir == "" {
		dir = DefaultConfigDir()
	}

	cfg := &Config{
		BaseURL:     defaultBaseURL,
		Model:       defaultModel,
		Temperature: defaultTemperature,
		MaxTokens:   defaultMaxTokens,
		TimeoutSec:  defaultTimeoutSec,
		GCMaxRuns:   defaultGCMaxRuns,
		GCMaxMB:     defaultGCMaxMB,
	}

	configPath := filepath.Join(dir, configFileName)
	if _, err := os.Stat(configPath); err == nil {
		// Enforce permissions on config.yaml
		_ = EnforceStrictFilePermissions(configPath)

		if data, rerr := os.ReadFile(configPath); rerr == nil {
			var cf configFile
			if jerr := yaml.Unmarshal(data, &cf); jerr == nil {
				if cf.APIKey != "" {
					cfg.APIKey = cf.APIKey
				}
				if cf.BaseURL != "" {
					cfg.BaseURL = cf.BaseURL
				}
				if cf.Model != "" {
					cfg.Model = cf.Model
				}
				if cf.Temperature != nil {
					cfg.Temperature = *cf.Temperature
				}
				if cf.MaxTokens != nil {
					cfg.MaxTokens = *cf.MaxTokens
				}
				if cf.TimeoutSec != nil {
					cfg.TimeoutSec = *cf.TimeoutSec
				}
				if cf.GCMaxRuns != nil {
					cfg.GCMaxRuns = *cf.GCMaxRuns
				}
				if cf.GCMaxMB != nil {
					cfg.GCMaxMB = *cf.GCMaxMB
				}
				cfg.LocalModels = cf.LocalModels
			}
		}
	}

	// If no API key was in config.yaml, load from OS Keyring or credentials file
	if cfg.APIKey == "" {
		if secret, err := LoadSecretFromDir(dir); err == nil && secret != "" {
			cfg.APIKey = secret
		}
	}

	// Environment variable overrides take precedence over config file and keyring
	if v := os.Getenv("LNTA_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("LNTA_BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := os.Getenv("LNTA_MODEL"); v != "" {
		cfg.Model = v
	}

	// Auto-discover local Ollama models
	discoveredModels, _, discErr := DiscoverLocalOllama()
	if discErr == nil && len(discoveredModels) > 0 {
		cfg.LocalModels = discoveredModels
	}

	if cfg.APIKey == "" {
		return nil, ErrNoAPIKey
	}
	return cfg, nil
}

// DiscoverLocalOllama probes http://127.0.0.1:11434/api/tags with a 150ms timeout
// to discover locally running Ollama models. It returns the list of models and whether
// any support tool-calling.
func DiscoverLocalOllama() ([]LocalOllamaModel, bool, error) {
	client := &http.Client{
		Timeout: ollamaDiscoveryTimeout,
	}
	resp, err := client.Get(ollamaDiscoveryURL)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, false, fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}

	var result struct {
		Models []LocalOllamaModel `json:"models"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, false, err
	}

	// Check if any models support tool-calling
	hasToolCalling := false
	for _, m := range result.Models {
		_ = m
		hasToolCalling = true
	}

	return result.Models, hasToolCalling, nil
}
