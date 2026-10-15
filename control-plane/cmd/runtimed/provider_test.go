package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/runtime"
)

func TestPrivateProviderConnectionMemoryOnly(t *testing.T) {
	boot := time.Now().UTC()
	a := &app{bootedAt: boot}
	t.Setenv("RUNTIMED_ANTHROPIC_PROXY", "http://sandboxd:9100")
	p := runtime.ProviderConnection{ID: base64.RawURLEncoding.EncodeToString(make([]byte, 16)), Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		BaseURL: "http://sandboxd:9100/apps/test-app/anthropic", ExpiresAt: boot.Add(time.Hour), BootedAt: boot}
	call := func(a *app, method, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.handleProviderConnection(w, httptest.NewRequest(method, "/provider-connection", strings.NewReader(body)))
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable provider response")
		}
		return w
	}
	if w := call(a, "GET", ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	body, _ := json.Marshal(p)
	if w := call(a, "PUT", string(body)); w.Code != 204 || w.Body.Len() != 0 {
		t.Fatal(w.Code)
	}
	if w := call(a, "GET", ""); w.Code != 200 || !strings.Contains(w.Body.String(), p.Token) {
		t.Fatal("private connection unavailable")
	}
	status, _ := json.Marshal(a.status())
	if strings.Contains(string(status), p.Token) || strings.Contains(string(status), p.ID) {
		t.Fatal("status leaked connection")
	}
	for _, change := range []func(*runtime.ProviderConnection){
		func(p *runtime.ProviderConnection) { p.BaseURL = "https://attacker.invalid/apps/test-app/anthropic" },
		func(p *runtime.ProviderConnection) { p.BaseURL += "?token=leak" },
		func(p *runtime.ProviderConnection) { p.BaseURL += "?" },
		func(p *runtime.ProviderConnection) { p.BaseURL = "http://sandboxd:9100/apps/../anthropic" },
		func(p *runtime.ProviderConnection) { p.BaseURL = "http://sandboxd:9100/apps/%74est-app/anthropic" },
		func(p *runtime.ProviderConnection) { p.Token = "real-provider-key" },
		func(p *runtime.ProviderConnection) { p.ID = "../file" },
		func(p *runtime.ProviderConnection) { p.BootedAt = boot.Add(time.Nanosecond) },
		func(p *runtime.ProviderConnection) { p.ExpiresAt = boot.Add(-time.Second) },
		func(p *runtime.ProviderConnection) { p.ExpiresAt = boot.Add(48 * time.Hour) },
	} {
		bad := p
		change(&bad)
		raw, _ := json.Marshal(bad)
		w := call(a, "PUT", string(raw))
		if w.Code != 400 || strings.Contains(w.Body.String(), p.Token) {
			t.Fatal("invalid delivery accepted or echoed")
		}
	}
	for _, raw := range []string{string(body) + `{}`, `{"unknown":true}`, strings.Repeat(" ", 4096) + string(body)} {
		if w := call(a, "PUT", raw); w.Code != 400 {
			t.Fatal("invalid JSON accepted")
		}
	}
	// A new supervisor cannot inherit an old connection or accept stale delivery.
	restarted := &app{bootedAt: boot.Add(time.Second)}
	if w := call(restarted, "GET", ""); w.Code != 404 {
		t.Fatal("connection survived boot")
	}
	if w := call(restarted, "PUT", string(body)); w.Code != 400 {
		t.Fatal("stale delivery accepted")
	}
	a.provider.ExpiresAt = time.Now().Add(-time.Second)
	if w := call(a, "GET", ""); w.Code != 404 || a.provider != nil {
		t.Fatal("expired connection retained")
	}
}
