package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

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
	// ollamaDiscoveryTimeout is the timeout for Ollama discovery.
	ollamaDiscoveryTimeout = 150 * time.Millisecond
	// ollamaBaseURL is the OpenAI-compatible endpoint exposed by a local
	// Ollama server, used for 100% offline --local mode.
	ollamaBaseURL = "http://127.0.0.1:11434/v1"
)

// ollamaDiscoveryURL is the URL to probe for local Ollama models.
// It is a var (not const) so tests can point it at an httptest server.
var ollamaDiscoveryURL = "http://127.0.0.1:11434/api/tags"

// LocalOllamaModel represents a model discovered from a local Ollama instance.
// Ollama's /api/tags returns "name", "size", "modified_at" fields.
type LocalOllamaModel struct {
	ID      string `yaml:"id" json:"name"`
	Size    int64  `yaml:"size" json:"size,omitempty"`
	Modified string `yaml:"modified" json:"modified_at,omitempty"`
}

// Config holds the LLM agent configuration. Values are loaded from
// ~/.config/lnta/config.yaml with environment variable overrides (env wins over
// file). It supports any OpenAI-compatible API (via go-openai), Ollama local
// models, or Anthropic/Gemini endpoints that expose an OpenAI-compatible chat
// completions endpoint.
type Config struct {
	APIKey         string               `yaml:"api_key"`
	BaseURL        string               `yaml:"base_url"`
	Model          string               `yaml:"model"`
	Temperature    float32              `yaml:"temperature"`
	MaxTokens      int                  `yaml:"max_tokens"`
	TimeoutSec     int                  `yaml:"timeout_sec"`
	LocalModels    []LocalOllamaModel   `yaml:"local_models,omitempty" json:"local_models,omitempty"`
}

// configFile is the on-disk representation of Config with optional fields.
type configFile struct {
	APIKey        string               `yaml:"api_key"`
	BaseURL       string               `yaml:"base_url"`
	Model         string               `yaml:"model"`
	Temperature   *float32             `yaml:"temperature"`
	MaxTokens     *int                 `yaml:"max_tokens"`
	TimeoutSec    *int                 `yaml:"timeout_sec"`
	LocalModels   []LocalOllamaModel   `yaml:"local_models,omitempty"`
}

// LoadConfig loads the agent config from ~/.config/lnta/config.yaml, applying
// sensible defaults and environment variable overrides:
//   LNTA_API_KEY, LNTA_BASE_URL, LNTA_MODEL.
//
// A missing config file is not an error; defaults and env vars are used
// instead. An empty API key is an error because the agent cannot function
// without an LLM endpoint.
//
// Local Ollama models are auto-discovered via http://127.0.0.1:11434/api/tags
// with a 150ms timeout.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		BaseURL:     defaultBaseURL,
		Model:       defaultModel,
		Temperature: defaultTemperature,
		MaxTokens:   defaultMaxTokens,
		TimeoutSec:  defaultTimeoutSec,
	}

	home, err := os.UserHomeDir()
	if err == nil {
		path := filepath.Join(home, ".config", "lnta", configFileName)
		if data, rerr := os.ReadFile(path); rerr == nil {
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
				cfg.LocalModels = cf.LocalModels
			}
		}
	}

	// Environment variable overrides take precedence over the config file.
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
		return nil, fmt.Errorf(
		"no LLM API key configured: set LNTA_API_KEY or ~/.config/lnta/config.yaml api_key")
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
		return nil, false, fmt.Errorf("Ollama returned status %d", resp.StatusCode)
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

	// Check if any models support tool-calling (they have 'tool_calls' capability)
	hasToolCalling := false
	for _, m := range result.Models {
		// Models that support tool-calling typically have certain characteristics
		// We'll consider any model as potentially supporting tool-calling
		// since Ollama models can vary in capabilities
		_ = m
		hasToolCalling = true // Assume all discovered models could support it
	}

	return result.Models, hasToolCalling, nil
}