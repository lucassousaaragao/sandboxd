package provideraccess

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

func renewalFixture(t *testing.T) (*fixture, Grant, ConnectionInfo) {
	t.Helper()
	f := setup(t)
	if err := f.s.Create(context.Background(), &store.Sandbox{ID: "runtime-a", AppID: sql.NullString{String: "app-a", Valid: true}, Status: "running", Image: "test"}); err != nil {
		t.Fatal(err)
	}
	g, err := f.b.IssueRuntime(context.Background(), "owner", "app-a", "MODEL_KEY", "anthropic", "runtime-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return f, g, ConnectionInfo{ID: g.ID, ExpiresAt: g.ExpiresAt}
}

func TestRenewalRetainsTokenAcrossOriginalExpiryAndBrokerRestart(t *testing.T) {
	f, g, initial := renewalFixture(t)
	ctx := context.Background()
	f.now = f.now.Add(30 * time.Minute)
	next, err := f.b.RenewRuntime(ctx, "owner", "app-a", "runtime-a", initial, 24*time.Hour)
	if err != nil || next.ID != initial.ID || !next.ExpiresAt.Equal(f.now.Add(24*time.Hour)) {
		t.Fatalf("renewal=%+v err=%v", next, err)
	}
	if _, err := f.b.RenewRuntime(ctx, "owner", "app-a", "runtime-a", initial, time.Hour); !errors.Is(err, ErrDenied) {
		t.Fatal("stale expiry compare-and-swap accepted")
	}
	shorter, err := f.b.RenewRuntime(ctx, "owner", "app-a", "runtime-a", next, time.Minute)
	if err != nil || shorter != next {
		t.Fatal("renewal shortened an existing lease")
	}
	f.now = initial.ExpiresAt.Add(time.Second)
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	fakeSuccess(f.b)
	requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, `{}`), 200)
	info, err := f.b.RuntimeConnection(ctx, "owner", "app-a", "runtime-a")
	if err != nil || info != next {
		t.Fatal("connection metadata not retained")
	}
	var count int
	if err := f.s.DB().QueryRow(`SELECT count(*) FROM provider_grant`).Scan(&count); err != nil || count != 1 {
		t.Fatal("renewal accumulated grants")
	}
	f.now = next.ExpiresAt
	requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, `{}`), 401)
	if _, err := f.b.RenewRuntime(ctx, "owner", "app-a", "runtime-a", next, time.Hour); !errors.Is(err, ErrDenied) {
		t.Fatal("expired access revived")
	}
}

func TestRenewalCannotReviveChangedPermissionsOrLifecycle(t *testing.T) {
	for _, mutation := range []string{
		`UPDATE app_config SET access_policy='agent_access' WHERE app_id='app-a'`,
		`UPDATE app_config SET access_policy='agent_access' WHERE app_id='app-a'; UPDATE app_config SET access_policy='runtime_access' WHERE app_id='app-a'`,
		`UPDATE app_config SET value_ciphertext=x'00' WHERE app_id='app-a'`,
		`DELETE FROM app_config WHERE app_id='app-a'`,
		`UPDATE app SET owner_token='other' WHERE id='app-a'`,
		`DELETE FROM app WHERE id='app-a'`,
		`UPDATE sandbox SET status='stopped' WHERE id='runtime-a'`,
		`UPDATE sandbox SET status='stopped' WHERE id='runtime-a'; UPDATE sandbox SET status='running' WHERE id='runtime-a'`,
		`UPDATE sandbox SET app_id='app-b' WHERE id='runtime-a'`,
		`DELETE FROM sandbox WHERE id='runtime-a'`,
		`DELETE FROM provider_grant`,
	} {
		t.Run(mutation, func(t *testing.T) {
			f, g, info := renewalFixture(t)
			if _, err := f.s.DB().Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if _, err := f.b.RenewRuntime(context.Background(), "owner", "app-a", "runtime-a", info, 24*time.Hour); !errors.Is(err, ErrDenied) {
				t.Fatalf("revived access: %v", err)
			}
			if _, err := f.b.RuntimeConnection(context.Background(), "owner", "app-a", "runtime-a"); !errors.Is(err, ErrDenied) {
				t.Fatal("invalid connection metadata returned")
			}
			requireStatus(t, request(f.b, "POST", "/apps/app-a/anthropic/v1/messages", g.Token, `{}`), 401)
		})
	}
}

func TestRenewalValidatesBindingAndNeverAdoptsAnUnboundGrant(t *testing.T) {
	f, _, info := renewalFixture(t)
	ctx := context.Background()
	for _, pair := range [][3]string{{"other", "app-a", "runtime-a"}, {"owner", "app-b", "runtime-a"}, {"owner", "app-a", "runtime-b"}, {"", "app-a", "runtime-a"}} {
		if _, err := f.b.RenewRuntime(ctx, pair[0], pair[1], pair[2], info, time.Hour); !errors.Is(err, ErrDenied) {
			t.Fatal("wrong binding renewed")
		}
		if _, err := f.b.RuntimeConnection(ctx, pair[0], pair[1], pair[2]); !errors.Is(err, ErrDenied) {
			t.Fatal("wrong binding disclosed")
		}
	}
	for _, ttl := range []time.Duration{0, time.Second, 24*time.Hour + time.Second} {
		if _, err := f.b.RenewRuntime(ctx, "owner", "app-a", "runtime-a", info, ttl); !errors.Is(err, ErrDenied) {
			t.Fatal("invalid ttl renewed")
		}
	}
	unbound := f.issue(t)
	if _, err := f.b.RenewRuntime(ctx, "owner", "app-a", "runtime-a", ConnectionInfo{ID: unbound.ID, ExpiresAt: unbound.ExpiresAt}, time.Hour); !errors.Is(err, ErrDenied) {
		t.Fatal("unbound grant adopted")
	}
	next, err := f.b.IssueRuntime(ctx, "owner", "app-a", "MODEL_KEY", "anthropic", "runtime-a", time.Hour)
	if err != nil || next.ID == info.ID {
		t.Fatal(err)
	}
	if _, err := f.b.RenewRuntime(ctx, "owner", "app-a", "runtime-a", info, time.Hour); !errors.Is(err, ErrDenied) {
		t.Fatal("replaced grant revived")
	}
}
