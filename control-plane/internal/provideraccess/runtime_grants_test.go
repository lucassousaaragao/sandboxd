package provideraccess

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

func TestRuntimeGrantsBindRotateAndRevoke(t *testing.T) {
	for _, mutation := range []string{
		`UPDATE sandbox SET status='stopped' WHERE id='runtime-a'`,
		`UPDATE sandbox SET app_id='app-b' WHERE id='runtime-a'`,
		`DELETE FROM sandbox WHERE id='runtime-a'`,
	} {
		t.Run(mutation, func(t *testing.T) {
			f := setup(t)
			fakeSuccess(f.b)
			ctx := context.Background()
			if err := f.s.Create(ctx, &store.Sandbox{ID: "runtime-a", AppID: sql.NullString{String: "app-a", Valid: true}, Status: "running", Image: "test"}); err != nil {
				t.Fatal(err)
			}
			issue := func(owner, app string) (Grant, error) {
				return f.b.IssueRuntime(ctx, owner, app, "MODEL_KEY", "anthropic", "runtime-a", time.Hour)
			}
			g, err := issue("owner", "app-a")
			if err != nil {
				t.Fatal(err)
			}
			requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, `{}`), 200)
			for _, pair := range [][2]string{{"other", "app-a"}, {"owner", "app-b"}} {
				if _, err := issue(pair[0], pair[1]); !errors.Is(err, ErrDenied) {
					t.Fatal("cross-owner/app grant issued")
				}
			}
			// Failed issuance must leave the original valid grant intact.
			requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, `{}`), 200)
			next, err := issue("owner", "app-a")
			if err != nil {
				t.Fatal(err)
			}
			requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, `{}`), 401)
			requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", next.Token, `{}`), 200)
			unbound := f.issue(t)
			if _, err = f.s.DB().Exec(mutation); err != nil {
				t.Fatal(err)
			}
			requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", next.Token, `{}`), 401)
			// Existing trusted-caller grants retain their documented semantics.
			requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", unbound.Token, `{}`), 200)
			if _, err := issue("owner", "app-a"); !errors.Is(err, ErrDenied) {
				t.Fatal("inactive runtime issued grant")
			}
			if _, err = f.s.DB().Exec(`UPDATE sandbox SET status='running', app_id='app-a' WHERE id='runtime-a'`); err != nil {
				t.Fatal(err)
			}
			requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", next.Token, `{}`), 401)
		})
	}
}
