package resourcebudget

import (
	"encoding/json"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/docker"
	"testing"
)

func TestDefaultsAndConfiguredLimits(t *testing.T) {
	defaults, err := FromEnv(func(string) string { return "" })
	if err != nil || defaults != Default() {
		t.Fatalf("defaults: %+v %v", defaults, err)
	}
	var spec docker.RunSpec
	defaults.Apply(&spec)
	if spec.Memory != "10g" || spec.MemorySwap != "10g" || spec.CPULimit != "" || spec.CPUShares != 100 || spec.PidsLimit != 1024 {
		t.Fatalf("legacy defaults changed: %+v", spec)
	}
	env := map[string]string{"SANDBOXD_SANDBOX_MEMORY_MIB": "2048", "SANDBOXD_SANDBOX_CPU_MILLICORES": "1500", "SANDBOXD_SANDBOX_PIDS_LIMIT": "256"}
	limits, err := FromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	spec = docker.RunSpec{ReadOnly: true, Volumes: []string{"owned:/home/sandbox"}, SecurityOpt: []string{"no-new-privileges"}, Image: "fixture"}
	limits.Apply(&spec)
	if spec.Memory != "2048m" || spec.MemorySwap != spec.Memory || spec.CPULimit != "1.500" || spec.PidsLimit != 256 || !spec.ReadOnly || len(spec.Volumes) != 1 || len(spec.SecurityOpt) != 1 || spec.Image != "fixture" {
		t.Fatalf("incorrect spec: %+v", spec)
	}
}

func TestRejectInvalidConfiguration(t *testing.T) {
	for key, invalid := range map[string][]string{
		"SANDBOXD_SANDBOX_MEMORY_MIB":     {"0", "255", "65537", "2g", "-1", " 2048", "2048 ", "1.5", "99999999999999999999999"},
		"SANDBOXD_SANDBOX_CPU_MILLICORES": {"-1", "1", "99", "64001", "1e3", "+100"},
		"SANDBOXD_SANDBOX_PIDS_LIMIT":     {"0", "63", "65537", "1024\n"},
	} {
		for _, value := range invalid {
			t.Run(key+"/"+value, func(t *testing.T) {
				_, err := FromEnv(func(k string) string {
					if k == key {
						return value
					}
					return ""
				})
				if err == nil {
					t.Fatal("invalid limits accepted")
				}
			})
		}
	}
}

func TestInspectLimitMatching(t *testing.T) {
	limits := Limits{MemoryMiB: 2048, CPUMillicores: 1500, Pids: 256}
	var container docker.ContainerJSON
	if limits.Matches(nil) || limits.Matches(&container) {
		t.Fatal("unknown state accepted")
	}
	if err := json.Unmarshal([]byte(`{"HostConfig":{"Memory":2147483648,"MemorySwap":2147483648,"NanoCpus":1500000000,"PidsLimit":256}}`), &container); err != nil {
		t.Fatal(err)
	}
	if !limits.Matches(&container) {
		t.Fatal("correct limits rejected")
	}
	container.HostConfig.NanoCPUs = 0
	if limits.Matches(&container) {
		t.Fatal("unlimited CPU accepted")
	}
	container.HostConfig.NanoCPUs = 1500000000
	container.HostConfig.MemorySwap = -1
	if limits.Matches(&container) {
		t.Fatal("unlimited swap accepted")
	}
	container.HostConfig.MemorySwap = container.HostConfig.Memory
	container.HostConfig.PidsLimit = nil
	if limits.Matches(&container) {
		t.Fatal("missing PID limit accepted")
	}
}
