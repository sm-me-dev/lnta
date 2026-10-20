package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestDiscoverLocalOllamaSuccess verifies Ollama model discovery against a
// mock server returning models with tool-calling support.
func TestDiscoverLocalOllamaSuccess(t *testing.T) {
	// Save and override the discovery URL.
	origURL := ollamaDiscoveryURL
	defer func() { ollamaDiscoveryURL = origURL }()

	// Mock Ollama /api/tags response.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{
			"models": []map[string]any{
				{"name": "qwen2.5-coder:7b", "size": 4381234567, "modified_at": "2024-01-01T00:00:00Z"},
				{"name": "llama3.3:70b", "size": 39812345678, "modified_at": "2024-01-02T00:00:00Z"},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	ollamaDiscoveryURL = server.URL + "/api/tags"

	models, hasToolCalling, err := DiscoverLocalOllama()
	if err != nil {
		t.Fatalf("DiscoverLocalOllama() returned error: %v", err)
	}

	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d", len(models))
	}
	if models[0].ID != "qwen2.5-coder:7b" {
		t.Errorf("first model ID = %q, want %q", models[0].ID, "qwen2.5-coder:7b")
	}
	if models[0].Size != 4381234567 {
		t.Errorf("first model size = %d, want %d", models[0].Size, 4381234567)
	}
	if !hasToolCalling {
		t.Error("expected hasToolCalling to be true when models are discovered")
	}
}

// TestDiscoverLocalOllamaConnectionRefused verifies fallback when Ollama is
// not running (connection refused), returning no error but empty models.
func TestDiscoverLocalOllamaConnectionRefused(t *testing.T) {
	origURL := ollamaDiscoveryURL
	defer func() { ollamaDiscoveryURL = origURL }()

	// Point to a port that nothing is listening on.
	ollamaDiscoveryURL = "http://127.0.0.1:1"

	// The call should return quickly due to the 150ms timeout, not hang.
	start := time.Now()
	models, _, err := DiscoverLocalOllama()
	elapsed := time.Since(start)

	// Expect an error (connection refused/timeout) and no models.
	if err == nil {
		t.Error("expected DiscoverLocalOllama() to return error when Ollama is not running")
	}
	if models != nil {
		t.Errorf("expected nil models on error, got %d models", len(models))
	}
	// Should fail fast (< 2 seconds), not hang indefinitely.
	if elapsed > 2*time.Second {
		t.Errorf("DiscoverLocalOllama() took %v, expected fast failure due to 150ms timeout", elapsed)
	}
}

// TestDiscoverLocalOllamaNon200 verifies handling of non-200 responses.
func TestDiscoverLocalOllamaNon200(t *testing.T) {
	origURL := ollamaDiscoveryURL
	defer func() { ollamaDiscoveryURL = origURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ollamaDiscoveryURL = server.URL

	_, _, err := DiscoverLocalOllama()
	if err == nil {
		t.Error("expected DiscoverLocalOllama() to return error on non-200 status")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error should mention 500 status, got: %v", err)
	}
}

// TestDiscoverLocalOllamaInvalidJSON verifies handling of invalid JSON body.
func TestDiscoverLocalOllamaInvalidJSON(t *testing.T) {
	origURL := ollamaDiscoveryURL
	defer func() { ollamaDiscoveryURL = origURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, "not valid json{{{")
	}))
	defer server.Close()

	ollamaDiscoveryURL = server.URL

	_, _, err := DiscoverLocalOllama()
	if err == nil {
		t.Error("expected DiscoverLocalOllama() to return error on invalid JSON")
	}
}

// TestLoadConfigAutoDiscoversOllama verifies that LoadConfig auto-discovers
// Ollama models when no config file exists.
func TestLoadConfigAutoDiscoversOllama(t *testing.T) {
	origURL := ollamaDiscoveryURL
	defer func() { ollamaDiscoveryURL = origURL }()

	// Set API key so LoadConfig doesn't fail.
	origKey := os.Getenv("LNTA_API_KEY")
	os.Setenv("LNTA_API_KEY", "test-key")
	defer os.Setenv("LNTA_API_KEY", origKey)

	// Mock Ollama returning one model.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{
			"models": []map[string]any{
				{"name": "qwen2.5-coder:7b", "size": 1234, "modified_at": "2024-01-01"},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	ollamaDiscoveryURL = server.URL + "/api/tags"

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() returned error: %v", err)
	}

	if len(cfg.LocalModels) != 1 {
		t.Fatalf("expected 1 auto-discovered local model, got %d", len(cfg.LocalModels))
	}
	if cfg.LocalModels[0].ID != "qwen2.5-coder:7b" {
		t.Errorf("local model ID = %q, want %q", cfg.LocalModels[0].ID, "qwen2.5-coder:7b")
	}
}

// TestLocalOllamaModelStruct verifies the LocalOllamaModel struct fields.
func TestLocalOllamaModelStruct(t *testing.T) {
	model := LocalOllamaModel{
		ID:      "test-model:7b",
		Size:    1024,
		Modified: "2024-01-01",
	}
	if model.ID != "test-model:7b" {
		t.Errorf("ID = %q, want %q", model.ID, "test-model:7b")
	}
	if model.Size != 1024 {
		t.Errorf("Size = %d, want %d", model.Size, 1024)
	}
	if model.Modified != "2024-01-01" {
		t.Errorf("Modified = %q, want %q", model.Modified, "2024-01-01")
	}
}

// TestOllamaDiscoveryTimeout verifies that DiscoverLocalOllama uses a
// 150ms timeout by checking that a slow server causes a timeout error.
func TestOllamaDiscoveryTimeout(t *testing.T) {
	origURL := ollamaDiscoveryURL
	defer func() { ollamaDiscoveryURL = origURL }()

	// Slow server that delays response beyond 150ms.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"models":[]}`)
	}))
	defer server.Close()

	ollamaDiscoveryURL = server.URL + "/api/tags"

	start := time.Now()
	_, _, err := DiscoverLocalOllama()
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected DiscoverLocalOllama() to timeout on slow server")
	}
	// Should time out around 150ms, not wait the full 500ms.
	if elapsed > 1*time.Second {
		t.Errorf("DiscoverLocalOllama() took %v, expected timeout around 150ms", elapsed)
	}
}
