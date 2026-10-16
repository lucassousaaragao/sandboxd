// Package resourcebudget defines operator-owned per-container hard limits.
// It has no Desktop, licensing, provider or host filesystem dependencies.
package resourcebudget

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tastyeffectco/sandboxd/control-plane/internal/docker"
)

type Limits struct {
	MemoryMiB     int `json:"memory_mib"`
	CPUMillicores int `json:"cpu_millicores"` // 0 preserves the existing unlimited CPU default.
	Pids          int `json:"pids"`
}

func Default() Limits { return Limits{MemoryMiB: 10240, Pids: 1024} }
func Effective(value *Limits) Limits {
	if value == nil {
		return Default()
	}
	return *value
}

func (l Limits) Validate() error {
	if l.MemoryMiB < 256 || l.MemoryMiB > 65536 {
		return fmt.Errorf("sandbox memory must be 256..65536 MiB")
	}
	if l.CPUMillicores != 0 && (l.CPUMillicores < 100 || l.CPUMillicores > 64000) {
		return fmt.Errorf("sandbox CPU must be 0 (unlimited) or 100..64000 millicores")
	}
	if l.Pids < 64 || l.Pids > 65536 {
		return fmt.Errorf("sandbox PID limit must be 64..65536")
	}
	return nil
}

func FromEnv(getenv func(string) string) (Limits, error) {
	l := Default()
	for _, item := range []struct {
		name  string
		value *int
	}{
		{"SANDBOXD_SANDBOX_MEMORY_MIB", &l.MemoryMiB},
		{"SANDBOXD_SANDBOX_CPU_MILLICORES", &l.CPUMillicores},
		{"SANDBOXD_SANDBOX_PIDS_LIMIT", &l.Pids},
	} {
		raw := getenv(item.name)
		if raw == "" {
			continue
		}
		if strings.Trim(raw, "0123456789") != "" {
			return Limits{}, fmt.Errorf("%s must be a decimal integer", item.name)
		}
		value, err := strconv.Atoi(raw)
		if err != nil {
			return Limits{}, fmt.Errorf("%s is out of range", item.name)
		}
		*item.value = value
	}
	return l, l.Validate()
}

// Apply only changes budget fields; isolation, mounts and command are preserved.
// Callers use validated startup settings. Nil settings preserve legacy behavior.
func (l Limits) Apply(spec *docker.RunSpec) {
	spec.Memory = fmt.Sprintf("%dm", l.MemoryMiB)
	if l.MemoryMiB == 10240 {
		spec.Memory = "10g"
	}
	spec.MemorySwap = spec.Memory // No additional swap, as before.
	spec.CPULimit = ""
	if l.CPUMillicores > 0 {
		spec.CPULimit = fmt.Sprintf("%d.%03d", l.CPUMillicores/1000, l.CPUMillicores%1000)
	}
	spec.CPUShares = 100
	spec.PidsLimit = l.Pids
}

func (l Limits) Matches(container *docker.ContainerJSON) bool {
	if container == nil || container.HostConfig == nil {
		return false
	}
	h := container.HostConfig
	return h.Memory == int64(l.MemoryMiB)*1024*1024 && h.MemorySwap == h.Memory &&
		h.NanoCPUs == int64(l.CPUMillicores)*1000000 && h.PidsLimit != nil && *h.PidsLimit == int64(l.Pids)
}
