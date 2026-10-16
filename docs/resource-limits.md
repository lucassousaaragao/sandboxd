# Operator resource ceilings

The engine accepts optional per-sandbox CPU, memory and process limits. These
are free engine configuration, not a Desktop dependency or subscription feature.
Defaults stay unchanged; there is no database migration or permanent service.

| Environment variable | Default | Allowed |
| --- | --- | --- |
| `SANDBOXD_SANDBOX_MEMORY_MIB` | 10240 | 256–65536 MiB |
| `SANDBOXD_SANDBOX_CPU_MILLICORES` | 0 | 0 (unlimited), or 100–64000 |
| `SANDBOXD_SANDBOX_PIDS_LIMIT` | 1024 | 64–65536 |

Empty means default. Only decimal integers are accepted; malformed/out-of-range
values fail startup before storage initialization. Memory plus swap equals the
memory ceiling (no additional swap), as before. CPU shares remain 100; an explicit
CPU quota is additional to those relative scheduling weights.

`GET /v1/settings` advertises `capabilities.runtime_resource_limits` and returns
`runtime.resource_limits`. This is the desired operator policy, not a measurement
or guarantee that every already-running container uses it. The public create and
settings APIs cannot raise or change these ceilings.

New containers and missing/image-replaced containers use the selected limits.
When an operator explicitly configures limits, starting a stopped container with
different limits recreates that container using the existing workspace. Matching
stopped containers are reused. Unknown Docker resource metadata/inspection errors
refuse the stopped start; they do not bypass the policy. Running containers are
not stopped or rebuilt solely because the operator changes the configuration.
Container-local temporary files are not durable; workspace data is retained.

This is **not** a complete desktop budget: aggregate memory/CPU admission, disk
quotas, free-space reporting, network policy and native VM resource management
remain separate. Multiple containers can collectively exhaust a small guest even
with per-container limits. Do not claim isolation or unattended availability from
these limits alone. Desktop must explicitly select and verify a policy with a
matching engine release; existing Windows downloads do not enable these settings.

## Verification

Unit tests cover configuration boundaries, default compatibility, Docker flags
through the public app-create path, safe read-only policy metadata, stopped
recreation and running-app preservation. Full Go tests, focused race checks and
vet are required.

The opt-in `scripts/test-resource-limits.mjs` takes two immutable image IDs:
`SANDBOXD_RESOURCE_TEST_ENGINE` must carry image label
`io.sandboxd.resource-limits-test=true`, and `SANDBOXD_RESOURCE_TEST_RUNTIME` must
match the native Linux Docker architecture. With `SANDBOXD_RESOURCE_LIMITS_LIVE=1`
it creates a fresh authenticated test engine, unique network and owned volume.
It verifies actual kernel cgroup CPU/memory/PID values, changes only its own stopped
sandbox's limits, starts through the API and verifies container replacement plus
retained workspace bytes. Matching restart reuses the replacement. Only owned
test resources are removed; ambiguous cleanup retains storage for inspection.
It does not call a model, start a preview edge, or prove Windows/macOS behavior.
