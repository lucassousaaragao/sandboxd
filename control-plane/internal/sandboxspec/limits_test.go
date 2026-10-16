package sandboxspec

import (
	"github.com/tastyeffectco/sandboxd/control-plane/internal/resourcebudget"
	"github.com/tastyeffectco/sandboxd/control-plane/internal/store"
	"testing"
)

func TestRecreatedSandboxUsesConfiguredLimits(t *testing.T) {
	limits := resourcebudget.Limits{MemoryMiB: 2048, CPUMillicores: 2000, Pids: 256}
	spec := Build(&store.Sandbox{ID: "fixture", WorkspaceMnt: "/owned/fixture"}, Env{Image: "image", Limits: &limits})
	if spec.Memory != "2048m" || spec.MemorySwap != spec.Memory || spec.CPULimit != "2.000" || spec.PidsLimit != 256 {
		t.Fatalf("limits lost on recreate: %+v", spec)
	}
	if !spec.ReadOnly || spec.Volumes[0] != "/owned/fixture:/home/sandbox" {
		t.Fatal("workspace/isolation changed")
	}
}
