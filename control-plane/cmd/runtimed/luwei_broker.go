package main

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
)

// Scoped capabilities are short-lived, not provider credentials. Only the
// LuweiDev-hosted broker can redeem them. No arbitrary outbound destination.
const luweiBrokerURL = "https://pvmgbfiwjotccmyhebct.supabase.co/functions/v1/opencode-broker/v1"

var luweiModelKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func writeLuweiBrokerConfig(model, ticket string) (string, string, error) {
	if ticket == "" {
		return "", "", nil
	}
	if len(ticket) > 4096 || !strings.HasPrefix(model, "openai/") {
		return "", "", errors.New("invalid Luwei broker capability/model")
	}
	id := strings.TrimPrefix(model, "openai/")
	if !luweiModelKey.MatchString(id) {
		return "", "", errors.New("invalid Luwei broker model")
	}
	cfg := map[string]any{
		"provider": map[string]any{
			"luwei": map[string]any{
				"npm":     "@ai-sdk/openai-compatible",
				"name":    "Luwei Harness",
				"options": map[string]any{"baseURL": luweiBrokerURL, "apiKey": ticket},
				"models":  map[string]any{id: map[string]any{"name": id}},
			},
		},
	}
	f, err := os.CreateTemp("", "luwei-opencode-*.json")
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(cfg); err != nil {
		os.Remove(f.Name())
		return "", "", err
	}
	return f.Name(), "luwei/" + id, nil
}
