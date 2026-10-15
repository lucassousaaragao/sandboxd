package provideraccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

// TaskUpstream matches the existing CLI routing, resolved by the trusted
// controller and delivered with the token so sandbox env cannot change its scope.
func TaskUpstream(agent, model, zen, region string) string {
	if agent == "claude-code" {
		return "anthropic"
	}
	if agent != "opencode" {
		return ""
	}
	id := model[strings.LastIndex(model, "/")+1:]
	if id == "MiniMax-M3" || id == "MiniMax-M2.7" {
		if region == "cn_zh" {
			return "minimax-cn"
		}
		return "minimax"
	}
	if zen == "zengo" {
		return "zengo"
	}
	return "zen"
}

func validTaskRoute(agent, upstream string) bool {
	return agent == "claude-code" && upstream == "anthropic" || agent == "opencode" && (upstream == "zen" || upstream == "zengo" || upstream == "minimax" || upstream == "minimax-cn")
}

// IssueTask uses a separate table from installed-app grants. A workload cannot
// exchange either kind of token for the other. The real provider key stays in
// the pre-existing credential store, not in this ticket or the runtime request.
func (b *Broker) IssueTask(ctx context.Context, owner, appID, sandboxID, taskID, agent, upstream string, ttl time.Duration) (string, error) {
	if owner == "" || !identifier(appID) || !identifier(sandboxID) || !identifier(taskID) || !validTaskRoute(agent, upstream) || ttl <= 0 || ttl > 24*time.Hour {
		return "", ErrDenied
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(entropy[:])
	hash := sha256.Sum256([]byte(tok))
	err := b.store.CreateTaskProxyGrant(ctx, store.TaskProxyGrant{TaskID: taskID, SandboxID: sandboxID, AppID: appID, OwnerToken: owner, Agent: agent, Upstream: upstream, TokenHash: hash[:], ExpiresAt: b.now().Add(ttl)})
	if err != nil {
		return "", ErrDenied
	}
	return tok, nil
}

func (b *Broker) RevokeTask(ctx context.Context, taskID string) error {
	return b.store.RevokeTaskProxyGrant(ctx, taskID)
}

// AuthorizeTask is called before shared credential resolution. No credential,
// network identity, dummy key, or installed-app grant can bypass this check.
func (b *Broker) AuthorizeTask(r *http.Request, agent, upstream string) bool {
	tok := token(r)
	if tok == "" || !validTaskRoute(agent, upstream) || r.URL.RawPath != "" {
		return false
	}
	path := strings.TrimPrefix(r.URL.Path, "/"+agent+"/"+upstream)
	allowed := false
	if upstream == "anthropic" {
		allowed = r.Method == "POST" && (path == "/v1/messages" || path == "/v1/messages/count_tokens") || r.Method == "GET" && path == "/v1/models"
		if r.URL.RawQuery != "" && r.URL.RawQuery != "beta=true" {
			return false
		}
	} else {
		allowed = r.Method == "POST" && (path == "/chat/completions" || path == "/responses") || r.Method == "GET" && path == "/models"
		if r.URL.RawQuery != "" {
			return false
		}
	}
	if !allowed {
		return false
	}
	hash := sha256.Sum256([]byte(tok))
	return b.store.CheckTaskProxyGrant(r.Context(), agent, upstream, hash[:], b.now())
}
