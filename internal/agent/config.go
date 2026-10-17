// Package agent implements the LLM agent loop: configuration, a strict tool
// registry, the orchestration pipeline, and the harness-enforced verification
// gate.
//
// See AGENTS.md "Architectural Non-Negotiables".
package agent

import (
	"fmt"
	"os"
	"path/filepath"

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
)

// Config holds the LLM agent configuration. Values are loaded from
// ~/.config/lnta/config.yaml with environment variable overrides (env wins over
// file). It supports any OpenAI-compatible API (via go-openai), Ollama local
// models, or Anthropic/Gemini endpoints that expose an OpenAI-compatible chat
// completions endpoint.
type Config struct {
	APIKey     string `yaml:"api_key"`
	BaseURL    string `yaml:"base_url"`
	Model      string `yaml:"model"`
	Temperature float32 `yaml:"temperature"`
	MaxTokens   int     `yaml:"max_tokens"`
	TimeoutSec  int     `yaml:"timeout_sec"`
}

// configFile is the on-disk representation of Config with optional fields.
type configFile struct {
	APIKey      string  `yaml:"api_key"`
	BaseURL     string  `yaml:"base_url"`
	Model       string  `yaml:"model"`
	Temperature *float32 `yaml:"temperature"`
	MaxTokens   *int    `yaml:"max_tokens"`
	TimeoutSec  *int    `yaml:"timeout_sec"`
}

// LoadConfig loads the agent config from ~/.config/lnta/config.yaml, applying
// sensible defaults and environment variable overrides:
//   LNTA_API_KEY, LNTA_BASE_URL, LNTA_MODEL.
//
// A missing config file is not an error; defaults and env vars are used
// instead. An empty API key is an error because the agent cannot function
// without an LLM endpoint.
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

	if cfg.APIKey == "" {
		return nil, fmt.Errorf(
			"no LLM API key configured: set LNTA_API_KEY or ~/.config/lnta/config.yaml api_key")
	}
	return cfg, nil
}
