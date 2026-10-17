package audit

import (
	"strings"
	"testing"
)

func TestRedactionBearerToken(t *testing.T) {
	got := redactString(`Authorization: Bearer abcdef1234567890deadbeef`)
	if !strings.Contains(got, "Bearer [REDACTED]") {
		t.Errorf("expected bearer token redacted, got %q", got)
	}
	if strings.Contains(got, "abcdef1234567890deadbeef") {
		t.Errorf("raw token still present: %q", got)
	}
}

func TestRedactionSKKey(t *testing.T) {
	got := redactString(`sk-ant-v1-1234567890abcdef1234567890ab`)
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected sk- key redacted, got %q", got)
	}
	if strings.Contains(got, "sk-ant-v1") {
		t.Errorf("raw sk- key still present: %q", got)
	}
}

func TestRedactionPasswordAssignment(t *testing.T) {
	got := redactString(`password=topsecretvalue123`)
	if !strings.Contains(got, "password=[REDACTED]") {
		t.Errorf("expected password redacted, got %q", got)
	}
	if strings.Contains(got, "topsecretvalue123") {
		t.Errorf("raw password still present: %q", got)
	}
}

func TestRedactionAPIKeyQuoted(t *testing.T) {
	got := redactString(`API_KEY="my-secret-key-value"`)
	if !strings.Contains(got, `API_KEY=[REDACTED]`) {
		t.Errorf("expected api_key redacted, got %q", got)
	}
	if strings.Contains(got, "my-secret-key-value") {
		t.Errorf("raw api key still present: %q", got)
	}
}

func TestRedactionPrivateKeyBlock(t *testing.T) {
	block := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC
-----END PRIVATE KEY-----`
	got := redactString("key: " + block + " end")
	if !strings.Contains(got, "[REDACTED PRIVATE KEY BLOCK]") {
		t.Errorf("expected private key block redacted, got %q", got)
	}
	if strings.Contains(got, "MIIEvQIBADAN") {
		t.Errorf("raw private key material still present: %q", got)
	}
}

func TestRedactionMap(t *testing.T) {
	out := redactMap(map[string]string{
		"token": "sk-1234567890abcdef1234567890ab",
		"safe":  "hello world",
	})
	if strings.Contains(out["token"], "sk-") {
		t.Errorf("token not redacted: %q", out["token"])
	}
	if out["safe"] != "hello world" {
		t.Errorf("safe value altered: %q", out["safe"])
	}
}
