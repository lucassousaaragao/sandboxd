package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/resourcebudget"
)

func TestAppCreateUsesOperatorResourceLimits(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(fmt.Sprint(configured), func(t *testing.T) {
			s, appID := appIdleServer(t)
			expected := resourcebudget.Default()
			if configured {
				expected = resourcebudget.Limits{MemoryMiB: 2048, CPUMillicores: 1500, Pids: 256}
				s.Limits = &expected
			}
			calls := filepath.Join(t.TempDir(), "calls")
			original, err := os.ReadFile(s.Docker.Bin)
			if err != nil {
				t.Fatal(err)
			}
			script := strings.Replace(string(original), "#!/bin/sh\n", fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" >> %q\n", calls), 1)
			if err := os.WriteFile(s.Docker.Bin, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			// Public request fields cannot override the trusted operator policy.
			w := appIdleRequest(s, appID, cfgTenant, `{"template":"blank","memory_mib":65536,"cpu_millicores":0,"pids":65536}`)
			if w.Code != 201 {
				t.Fatalf("create: %d %s", w.Code, w.Body)
			}
			raw, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			flags := string(raw)
			wants := []string{"--memory=10g", "--memory-swap=10g", "--pids-limit=1024", "--cpu-shares=100"}
			if configured {
				wants = []string{"--memory=2048m", "--memory-swap=2048m", "--pids-limit=256", "--cpus=1.500", "--cpu-shares=100"}
			}
			for _, want := range wants {
				if !strings.Contains(flags, "\n"+want+"\n") {
					t.Errorf("missing %s", want)
				}
			}
			if !configured && strings.Contains(flags, "--cpus=") {
				t.Fatal("legacy CPU cap changed")
			}
			if strings.Contains(flags, "--memory=65536") || strings.Contains(flags, "--pids-limit=65536") {
				t.Fatal("request overrode policy")
			}
			sb, err := s.Store.CurrentSandboxForApp(context.Background(), appID)
			if err != nil || sb == nil {
				t.Fatal("missing app sandbox", err)
			}
			settings := httptest.NewRecorder()
			s.v1GetSettings(settings, httptest.NewRequest("GET", "/v1/settings", nil))
			var view v1Settings
			if err := json.Unmarshal(settings.Body.Bytes(), &view); err != nil {
				t.Fatal(err)
			}
			if !view.Capabilities["runtime_resource_limits"] || view.Runtime.ResourceLimits != expected {
				t.Fatalf("policy descriptor: %+v", view.Runtime)
			}
			for _, field := range view.Editable {
				if strings.Contains(field, "resource_limits") {
					t.Fatal("operator policy is publicly editable")
				}
			}
		})
	}
}
