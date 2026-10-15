package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/runtime"
)

func TestProviderRenewalThroughRealSupervisorSocket(t *testing.T) {
	root, err := os.MkdirTemp("", "sbx-lease-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	boot := time.Now().UTC()
	t.Setenv("RUNTIMED_ANTHROPIC_PROXY", "http://sandboxd:9100")
	a := &app{bootedAt: boot, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	exited := make(chan error, 1)
	socket := filepath.Join(root, "sock")
	go func() { exited <- serve(ctx, socket, a) }()
	defer func() {
		cancel()
		if err := <-exited; err != nil {
			t.Error(err)
		}
	}()
	client := runtime.NewClient(socket)
	deadline := time.Now().Add(3 * time.Second)
	for {
		status, err := client.Status(ctx)
		if err == nil {
			if !status.ScopedProviderRenewal {
				t.Fatal("missing negotiation capability")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real supervisor did not listen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	p := runtime.ProviderConnection{ID: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), BaseURL: "http://sandboxd:9100/apps/app/anthropic", ExpiresAt: boot.Add(time.Hour), BootedAt: boot}
	if err := client.DeliverProviderConnection(ctx, p); err != nil {
		t.Fatal(err)
	}
	before, err := client.ProviderConnectionStatus(ctx)
	if err != nil || before.ID != p.ID || !before.ExpiresAt.Equal(p.ExpiresAt) {
		t.Fatal("delivery metadata mismatch", err)
	}
	next := runtime.ProviderConnectionRenewal{ProviderConnectionStatus: before, PreviousExpiresAt: before.ExpiresAt}
	next.ExpiresAt = boot.Add(23 * time.Hour)
	if err := client.RenewProviderConnection(ctx, next); err != nil {
		t.Fatal(err)
	}
	after, err := client.ProviderConnectionStatus(ctx)
	if err != nil || after != next.ProviderConnectionStatus {
		t.Fatal("renewal transport mismatch", err)
	}
	if err := client.RenewProviderConnection(ctx, next); err == nil {
		t.Fatal("stale transport renewal accepted")
	}
	a.providerMu.Lock()
	unchanged := a.provider.ID == p.ID && a.provider.Token == p.Token && a.provider.BaseURL == p.BaseURL
	a.providerMu.Unlock()
	if !unchanged {
		t.Fatal("real transport changed credential")
	}
}

func TestProviderRenewalPreservesProcessCredentialAndBoot(t *testing.T) {
	boot := time.Now().UTC()
	p := runtime.ProviderConnection{ID: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), BaseURL: "http://sandboxd:9100/apps/app/anthropic",
		ExpiresAt: boot.Add(time.Hour), BootedAt: boot}
	for _, kind := range []string{"valid", "same-expiry", "missing", "expired", "different-id", "different-boot", "stale-expiry", "shorten", "too-long", "unknown-field", "trailing-json", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			copy := p
			a := &app{bootedAt: boot, provider: &copy}
			next := runtime.ProviderConnectionRenewal{ProviderConnectionStatus: runtime.ProviderConnectionStatus{
				ID: p.ID, ExpiresAt: boot.Add(23 * time.Hour), BootedAt: boot}, PreviousExpiresAt: p.ExpiresAt}
			switch kind {
			case "same-expiry":
				next.ExpiresAt = p.ExpiresAt
			case "missing":
				a.provider = nil
			case "expired":
				a.provider.ExpiresAt = boot.Add(-time.Second)
				next.PreviousExpiresAt = a.provider.ExpiresAt
			case "different-id":
				next.ID = "another"
			case "different-boot":
				next.BootedAt = boot.Add(time.Second)
			case "stale-expiry":
				next.PreviousExpiresAt = boot.Add(30 * time.Minute)
			case "shorten":
				next.ExpiresAt = boot.Add(30 * time.Minute)
			case "too-long":
				next.ExpiresAt = boot.Add(25 * time.Hour)
			}
			raw, _ := json.Marshal(next)
			body := string(raw)
			switch kind {
			case "unknown-field":
				body = strings.TrimSuffix(body, "}") + `,"token":"do-not-accept"}`
			case "trailing-json":
				body += `{}`
			case "oversized":
				body = strings.Repeat(" ", 4096) + body
			}
			before, _ := json.Marshal(a.provider)
			w := httptest.NewRecorder()
			a.handleProviderConnectionRenewal(w, httptest.NewRequest("POST", "/provider-connection/renew", strings.NewReader(body)))
			valid := kind == "valid" || kind == "same-expiry"
			if (w.Code == 204) != valid || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unexpected renewal status %d", w.Code)
			}
			if valid {
				if a.provider.Token != p.Token || a.provider.BaseURL != p.BaseURL || a.provider.ID != p.ID || !a.provider.ExpiresAt.Equal(next.ExpiresAt) {
					t.Fatal("renewal replaced connection instead of extending expiry")
				}
				w := httptest.NewRecorder()
				a.handleProviderConnectionStatus(w, httptest.NewRequest("GET", "/provider-connection/status", nil))
				var status runtime.ProviderConnectionStatus
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status != next.ProviderConnectionStatus ||
					strings.Contains(w.Body.String(), p.Token) || strings.Contains(w.Body.String(), p.BaseURL) {
					t.Fatal("connection status leaked or changed identity")
				}
			} else {
				after, _ := json.Marshal(a.provider)
				if string(after) != string(before) {
					t.Fatal("rejected renewal mutated connection")
				}
			}
		})
	}
}
