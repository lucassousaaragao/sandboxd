package provideraccess

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

func taskFixture(t *testing.T) *fixture {
	f := setup(t)
	if err := f.s.Create(context.Background(), &store.Sandbox{ID: "sandbox-a", Status: "running", Image: "test", AppID: sql.NullString{String: "app-a", Valid: true}}); err != nil {
		t.Fatal(err)
	}
	return f
}

func issueTask(t *testing.T, f *fixture) string {
	t.Helper()
	tok, err := f.b.IssueTask(context.Background(), "owner", "app-a", "sandbox-a", "task-a", "claude-code", "anthropic", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func authorized(f *fixture, tok, path, agent, up string) bool {
	r := httptest.NewRequest("POST", path, nil)
	r.Header.Set("X-Api-Key", tok)
	return f.b.AuthorizeTask(r, agent, up)
}

func TestTaskGrantScopeAndRestart(t *testing.T) {
	f := taskFixture(t)
	tok := issueTask(t, f)
	if !authorized(f, tok, "/claude-code/anthropic/v1/messages?beta=true", "claude-code", "anthropic") {
		t.Fatal("valid task rejected")
	}
	for _, c := range []struct{ tok, path, agent, up string }{
		{"sandboxd-proxy-injected", "/claude-code/anthropic/v1/messages", "claude-code", "anthropic"},
		{tok, "/opencode/zen/chat/completions", "opencode", "zen"},
		{tok, "/claude-code/openai/responses", "claude-code", "openai"},
		{tok, "/claude-code/anthropic/v1/messages?url=evil", "claude-code", "anthropic"},
		{tok, "/claude-code/anthropic/v1/%6dessages", "claude-code", "anthropic"},
		{tok, "/claude-code/anthropic/v1/../admin", "claude-code", "anthropic"},
		{f.issue(t).Token, "/claude-code/anthropic/v1/messages", "claude-code", "anthropic"},
	} {
		if authorized(f, c.tok, c.path, c.agent, c.up) {
			t.Fatalf("scope bypass %s", c.path)
		}
	}
	requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", tok, "{}"), 401)
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	f.s = nil
	f.open(t)
	if !authorized(f, tok, "/claude-code/anthropic/v1/messages", "claude-code", "anthropic") {
		t.Fatal("restart lost unexpired task")
	}
	f.now = f.now.Add(time.Hour)
	if authorized(f, tok, "/claude-code/anthropic/v1/messages", "claude-code", "anthropic") {
		t.Fatal("expired task allowed")
	}
}

func TestTaskGrantOwnerAndRevocation(t *testing.T) {
	for _, action := range []string{"done", "stop", "owner", "revoke", "app-delete", "sandbox-delete"} {
		t.Run(action, func(t *testing.T) {
			f := taskFixture(t)
			ctx := context.Background()
			if _, err := f.b.IssueTask(ctx, "other", "app-a", "sandbox-a", "wrong-owner", "claude-code", "anthropic", time.Hour); err == nil {
				t.Fatal("wrong owner issued grant")
			}
			if _, err := f.b.IssueTask(ctx, "owner", "app-b", "sandbox-a", "wrong-app", "claude-code", "anthropic", time.Hour); err == nil {
				t.Fatal("wrong app issued grant")
			}
			tok := issueTask(t, f)
			var err error
			switch action {
			case "done":
				err = f.s.CreateTask(ctx, &store.Task{TaskID: "task-a", SandboxID: "sandbox-a", Agent: "claude-code", Prompt: "test"})
				if err != nil {
					t.Fatal(err)
				}
				err = f.s.FinishTask(ctx, "task-a", "succeeded", "{}")
			case "stop":
				_, err = f.s.DB().Exec(`UPDATE sandbox SET status='stopped' WHERE id='sandbox-a'; UPDATE sandbox SET status='running' WHERE id='sandbox-a'`)
			case "owner":
				_, err = f.s.DB().Exec(`UPDATE app SET owner_token='other' WHERE id='app-a'; UPDATE app SET owner_token='owner' WHERE id='app-a'`)
			case "revoke":
				err = f.b.RevokeTask(ctx, "task-a")
			case "app-delete":
				_, err = f.s.DB().Exec(`DELETE FROM app WHERE id='app-a'`)
			case "sandbox-delete":
				_, err = f.s.DB().Exec(`DELETE FROM sandbox WHERE id='sandbox-a'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if authorized(f, tok, "/claude-code/anthropic/v1/messages", "claude-code", "anthropic") {
				t.Fatal("revoked task allowed")
			}
		})
	}
}

func TestScopedModeAndTaskRouting(t *testing.T) {
	for _, c := range []struct {
		mode       string
		auth       bool
		url        string
		ok, scoped bool
	}{
		{"", false, "", true, false}, {"legacy", false, "", true, false}, {"scoped", true, "http://sandboxd:9100", true, true},
		{"scoped", false, "http://sandboxd:9100", false, false}, {"scoped", true, "", false, false},
		{"scoped", true, "http://user:password@host", false, false}, {"typo", true, "http://host", false, false},
	} {
		scoped, err := ScopedMode(c.mode, c.auth, c.url)
		if (err == nil) != c.ok || scoped != c.scoped {
			t.Fatalf("mode %q: %v %v", c.mode, scoped, err)
		}
	}
	for _, c := range []struct{ agent, model, zen, region, want string }{
		{"claude-code", "sonnet", "", "", "anthropic"}, {"opencode", "provider/MiniMax-M3", "zen", "cn_zh", "minimax-cn"},
		{"opencode", "MiniMax-M2.7", "zengo", "", "minimax"}, {"opencode", "big-pickle", "zengo", "", "zengo"},
		{"opencode", "big-pickle", "bad", "", "zen"}, {"unsupported", "", "", "", ""},
	} {
		if got := TaskUpstream(c.agent, c.model, c.zen, c.region); got != c.want {
			t.Fatalf("route=%s want=%s", got, c.want)
		}
	}
}
