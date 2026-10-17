package auth

import (
	"sync"
	"time"
)

// LuweiReplayGuard prevents duplicate signed requests within a bounded validity window.
// Deploy with shared storage or sticky routing if multiple control-plane replicas are used.
type LuweiReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (g *LuweiReplayGuard) Accept(signature string, now time.Time) bool {
	if signature == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = make(map[string]time.Time)
	}
	for key, expires := range g.seen {
		if !expires.After(now) {
			delete(g.seen, key)
		}
	}
	if expires, exists := g.seen[signature]; exists && expires.After(now) {
		return false
	}
	g.seen[signature] = now.Add(2 * time.Minute)
	return true
}
