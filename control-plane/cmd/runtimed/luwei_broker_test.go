package main

import (
	"os"
	"strings"
	"testing"
)

func TestLuweiBrokerConfig(t *testing.T) {
	path, model, err := writeLuweiBrokerConfig("openai/gpt-5.4", "test-scope-ticket")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	if model != "luwei/gpt-5.4" {
		t.Fatalf("model=%s", model)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe config permissions: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), luweiBrokerURL) || !strings.Contains(string(raw), "test-scope-ticket") {
		t.Fatal("broker provider configuration missing")
	}
	if strings.Contains(string(raw), "api.openai.com") {
		t.Fatal("direct provider URL must never be used")
	}
	if _, _, err := writeLuweiBrokerConfig("anthropic/claude", "ticket"); err == nil {
		t.Fatal("unsupported provider allowed")
	}
}
