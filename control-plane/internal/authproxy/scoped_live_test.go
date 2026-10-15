package authproxy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/agentauth"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/provideraccess"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/secrets"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

// Executed only by scripts/probe-scoped-cli.mjs in a fresh network-none,
// non-root container. This is a real CLI/tool loop with synthetic inference,
// not a provider subscription, Electron or native Windows compatibility test.
func TestLiveScopedCLI(t *testing.T) {
	if os.Getenv("SANDBOXD_LIVE_SCOPED_CLI") != "1" {
		t.Skip("requires disposable offline CLI probe")
	}
	if os.Getuid() != 1000 {
		t.Fatal("probe must run as sandbox uid")
	}
	agent := os.Getenv("SANDBOXD_LIVE_AGENT")
	if agent != "opencode" && agent != "claude-code" {
		t.Fatal("explicit supported CLI required")
	}
	up, endpoint, binary := "anthropic", "/v1/messages", "claude"
	if agent == "opencode" {
		up, endpoint, binary = "zen", "/chat/completions", "opencode"
	}
	migrations := os.Getenv("SANDBOXD_LIVE_MIGRATIONS")
	if migrations != "/home/sandbox/probe-migrations" {
		t.Fatal("explicit probe migrations required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	home := filepath.Join(root, "home")
	for _, dir := range []string{workspace, home} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	s, err := store.Open(ctx, filepath.Join(root, "state.db"), migrations)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := secrets.Load("", filepath.Join(root, "key"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := provideraccess.New(s, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateApp(ctx, &store.App{ID: "app-a", OwnerToken: "owner", Name: "CLI probe"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Create(ctx, &store.Sandbox{ID: "sandbox-a", AppID: sql.NullString{String: "app-a", Valid: true}, Status: "running", Image: "probe"}); err != nil {
		t.Fatal(err)
	}
	ticket, err := b.IssueTask(ctx, "owner", "app-a", "sandbox-a", "task-a", agent, up, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authStore := agentauth.NewStore(root)
	const providerKey = "synthetic-provider-only-key"
	writeAPIKey(t, authStore, agent, providerKey)
	var calls, tools, results atomic.Int32
	failures := make(chan string, 10)
	fail := func(message string) {
		select {
		case failures <- message:
		default:
		}
	}
	stubUpstream(t, up, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		credentialOK := r.Header.Get("X-Api-Key") == providerKey
		if agent == "opencode" {
			credentialOK = r.Header.Get("Authorization") == "Bearer "+providerKey
		}
		if !credentialOK || strings.Contains(fmt.Sprint(r.Header), ticket) {
			fail("credential substitution failed")
			w.WriteHeader(400)
			return
		}
		if r.URL.Path != endpoint {
			fail("unexpected upstream path: " + r.URL.Path)
			w.WriteHeader(400)
			return
		}
		var req struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
			Tools  []struct {
				Name     string `json:"name"`
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
			Messages []struct {
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
			fail("invalid model request")
			w.WriteHeader(400)
			return
		}
		hasWrite, hasResult := false, false
		for _, tool := range req.Tools {
			if tool.Name == "Write" || tool.Function.Name == "write" {
				hasWrite = true
			}
		}
		for _, message := range req.Messages {
			if message.Role == "tool" {
				hasResult = true
			}
			var blocks []struct {
				Type    string `json:"type"`
				IsError bool   `json:"is_error"`
			}
			if json.Unmarshal(message.Content, &blocks) == nil {
				for _, block := range blocks {
					if block.Type == "tool_result" {
						if block.IsError {
							fail("real CLI tool returned an error")
						}
						hasResult = true
					}
				}
			}
		}
		text, stop := "SCOPED_CLI_PROBE_COMPLETED", "end_turn"
		content := "written by the real " + agent + " CLI tool"
		block := map[string]any{"type": "text", "text": text}
		if hasWrite && !hasResult {
			tools.Add(1)
			stop = "tool_use"
			block = map[string]any{"type": "tool_use", "id": "tool_probe_write", "name": "Write", "input": map[string]any{"file_path": filepath.Join(workspace, "agent-written.txt"), "content": content}}
		} else if hasWrite && hasResult {
			results.Add(1)
		}
		if agent == "opencode" {
			// OpenCode also makes auxiliary requests (for example session titles)
			// without tools. The final assertions require the actual write loop.
			delta := map[string]any{"role": "assistant", "content": text}
			finish := "stop"
			if stop == "tool_use" {
				args, _ := json.Marshal(map[string]any{"filePath": filepath.Join(workspace, "agent-written.txt"), "content": content})
				delta = map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"index": 0, "id": "tool_probe_write", "type": "function", "function": map[string]any{"name": "write", "arguments": string(args)}}}}
				finish = "tool_calls"
			}
			if !req.Stream {
				fail("expected streaming OpenCode request")
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			chunk := func(d map[string]any, reason any) {
				data, _ := json.Marshal(map[string]any{"id": "chatcmpl-probe", "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": req.Model, "choices": []any{map[string]any{"index": 0, "delta": d, "finish_reason": reason}}})
				_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
				w.(http.Flusher).Flush()
			}
			chunk(delta, nil)
			chunk(map[string]any{}, finish)
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		message := map[string]any{"id": "msg_probe", "type": "message", "role": "assistant", "content": []any{block}, "model": req.Model, "stop_reason": stop, "stop_sequence": nil, "usage": map[string]any{"input_tokens": 100, "output_tokens": 30}}
		if !req.Stream {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(message)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		event := func(kind string, payload map[string]any) {
			payload["type"] = kind
			data, _ := json.Marshal(payload)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, data)
			w.(http.Flusher).Flush()
		}
		message["content"] = []any{}
		message["stop_reason"] = nil
		event("message_start", map[string]any{"message": message})
		var delta map[string]any
		if stop == "tool_use" {
			input, _ := json.Marshal(block["input"])
			block["input"] = map[string]any{}
			delta = map[string]any{"type": "input_json_delta", "partial_json": string(input)}
		} else {
			block["text"] = ""
			delta = map[string]any{"type": "text_delta", "text": text}
		}
		event("content_block_start", map[string]any{"index": 0, "content_block": block})
		event("content_block_delta", map[string]any{"index": 0, "delta": delta})
		event("content_block_stop", map[string]any{"index": 0})
		event("message_delta", map[string]any{"delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]any{"output_tokens": 30}})
		event("message_stop", map[string]any{})
	})
	proxy := httptest.NewServer(b.Gateway(NewScoped(authStore, nil, b.AuthorizeTask)))
	defer proxy.Close()
	version, err := exec.CommandContext(ctx, binary, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("CLI version: %v", err)
	}
	t.Logf("Real CLI version: %s", bytes.TrimSpace(version))
	cmd := exec.CommandContext(ctx, "claude", "-p", "--output-format", "stream-json", "--verbose", "--dangerously-skip-permissions", "--model", "sonnet", "Write agent-written.txt in this workspace using the Write tool, then report completion.")
	cmd.Dir = workspace
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + home, "LANG=C.UTF-8", "ANTHROPIC_BASE_URL=" + proxy.URL + "/claude-code/anthropic", "ANTHROPIC_API_KEY=" + ticket, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "DISABLE_AUTOUPDATER=1"}
	if agent == "opencode" {
		config := filepath.Join(root, "opencode.json")
		data, _ := json.Marshal(map[string]any{"provider": map[string]any{"proxy": map[string]any{"npm": "@ai-sdk/openai-compatible", "name": "proxy", "options": map[string]any{"baseURL": proxy.URL + "/opencode/zen", "apiKey": ticket}, "models": map[string]any{"probe-model": map[string]any{"name": "probe-model"}}}}})
		if err := os.WriteFile(config, data, 0600); err != nil {
			t.Fatal(err)
		}
		cmd = exec.CommandContext(ctx, "opencode", "run", "--format", "json", "--dangerously-skip-permissions", "--model", "proxy/probe-model", "Write agent-written.txt in this workspace using the write tool, then report completion.")
		cmd.Dir = workspace
		cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + home, "LANG=C.UTF-8", "OPENCODE_CONFIG=" + config, "OPENCODE_API_KEY=" + ticket, "OPENCODE_DISABLE_AUTOUPDATE=true"}
	}
	output, err := cmd.CombinedOutput()
	safe := strings.ReplaceAll(strings.ReplaceAll(string(output), ticket, "[task token]"), providerKey, "[synthetic provider key]")
	if len(safe) > 12000 {
		safe = safe[len(safe)-12000:]
	}
	if err != nil {
		t.Fatalf("real CLI failed: %v\n%s", err, safe)
	}
	select {
	case failure := <-failures:
		t.Fatal(failure)
	default:
	}
	if !strings.Contains(string(output), "SCOPED_CLI_PROBE_COMPLETED") {
		t.Fatalf("missing streamed completion: %s", safe)
	}
	if strings.Contains(string(output), ticket) || strings.Contains(string(output), providerKey) {
		t.Fatal("CLI output disclosed a credential")
	}
	written, err := os.ReadFile(filepath.Join(workspace, "agent-written.txt"))
	if err != nil || string(written) != "written by the real "+agent+" CLI tool" {
		t.Fatalf("real tool did not write expected file: %v", err)
	}
	if tools.Load() != 1 || results.Load() < 1 {
		t.Fatalf("tool loop incomplete: calls=%d tools=%d results=%d", calls.Load(), tools.Load(), results.Load())
	}
	if err = b.RevokeTask(ctx, "task-a"); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", proxy.URL+"/"+agent+"/"+up+endpoint, strings.NewReader("{}"))
	req.Header.Set("X-Api-Key", ticket)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("revoked task still authorized")
	}
	t.Logf("Real CLI write/tool-result/stream passed through scoped Go gateway; calls=%d. Revocation passed. Synthetic inference only.", calls.Load())
}
