package wake

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/resourcebudget"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
)

func TestResourceLimitWakePolicy(t *testing.T) {
	const id = "01WAKEDRIFT0000000000001"
	for _, tc := range []struct {
		name, state, hostConfig             string
		runningRow, recreate, start, denied bool
	}{
		{"matching stopped", "exited", `,"HostConfig":{"Memory":2147483648,"MemorySwap":2147483648,"NanoCpus":1000000000,"PidsLimit":256}`, false, false, true, false},
		{"drifted stopped", "exited", `,"HostConfig":{"Memory":10737418240,"MemorySwap":10737418240,"NanoCpus":0,"PidsLimit":1024}`, false, true, true, false},
		{"unknown config", "exited", "", false, false, false, true},
		{"inspect failed", "broken", "", false, false, false, true},
		{"missing container", "missing", "", false, true, true, false},
		{"running untouched", "running", "", true, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, st, calls := newDriftHandler(t, tc.state)
			if tc.hostConfig != "" {
				script, err := os.ReadFile(h.Docker.Bin)
				if err != nil {
					t.Fatal(err)
				}
				script = []byte(strings.Replace(string(script), `"Running":false}}`, `"Running":false}`+tc.hostConfig+`}`, 1))
				if err := os.WriteFile(h.Docker.Bin, script, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if !tc.runningRow {
				if err := st.MarkStopped(context.Background(), id); err != nil {
					t.Fatal(err)
				}
			}
			limits := resourcebudget.Limits{MemoryMiB: 2048, CPUMillicores: 1000, Pids: 256}
			h.Limits = &limits
			recreated := 0
			h.Recreate = func(context.Context, *store.Sandbox) error { recreated++; return nil }
			w := wakeJSON(h, id)
			if (recreated == 1) != tc.recreate || recreated > 1 {
				t.Fatalf("recreated %d times", recreated)
			}
			log, _ := os.ReadFile(calls)
			if strings.Contains(string(log), "start ") != tc.start {
				t.Fatalf("unexpected Docker calls: %s", log)
			}
			if strings.Contains(w.Body.String(), "resource_inspect_failed") != tc.denied {
				t.Fatalf("unexpected response: %s", w.Body)
			}
			if tc.runningRow && w.Code != 200 {
				t.Fatalf("running app interrupted: %s", w.Body)
			}
		})
	}
}
