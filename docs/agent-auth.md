# Agent auth &amp; context

How sandboxd gives a sandbox's coding agent its credentials — and its
environment context — **without** putting secrets in the workspace, snapshots,
container env, logs, events, or task results.

Two agents ship today behind one adapter interface: **opencode** and
**claude-code** are runnable (they have `runtimed` task adapters). **codex** is
runnable by the backend too but is **parked** — disabled/hidden in the UI until
its ChatGPT-subscription auth can be secured (see below). Every provider carries its **own**
credentials, connected by the owner and stored opaquely; a provider's material
is only ever used for that provider.

## Connecting a provider

`GET /v1/agents` lists providers with `installed_state`, `status`, `method`,
`supports_oauth`, `supports_api_key`, and `runnable`. Connect a provider three
ways (connecting **replaces** the provider's stored material atomically, so a
provider holds exactly one at a time):

| Method | Endpoint | Notes |
| --- | --- | --- |
| **API key** | `POST /v1/agents/{provider}/api-key` `{"api_key":"…"}` | Stored opaquely; injected as the provider's one key env var at task time. |
| **Import** | `POST /v1/agents/{provider}/import` `{"credentials":"…"}` | Paste the bundle your local `<cli> login` produced. Written verbatim, never parsed. |
| **Guided OAuth** (claude-code) | `POST /v1/agents/claude-code/oauth/start` → open URL → `…/oauth/finish` `{"code":"<code#state>"}` | A real `claude setup-token` **PKCE** flow, driven server-side. |

`POST /v1/agents/{provider}/disconnect` wipes the material. Stored
credentials are encrypted/opaque, never returned, echoed, logged, or emitted in
events; the console inputs are write-only. Auth changes take effect on the next
sandbox (re)create.

## How the credential reaches the agent — two models

### Every agent → credential-injecting proxy (the real credential never enters the sandbox)

When the auth proxy is enabled (`SANDBOXD_AGENT_PROXY_URL`, default
`http://sandboxd:9100`), **all** runnable agents reach their model provider
through a **reverse proxy control-plane-side** (`internal/authproxy`) that holds
the real credentials. No credential — API key or OAuth token — is mounted or
env-injected into the sandbox; the agent gets only a base URL and a **dummy**
key, and the proxy swaps in the real `Authorization` / `X-Api-Key` header on the
wire. A task can neither read, exfiltrate, nor clobber the credential.

Sandbox base URLs are `<proxy>/<agent>/<upstream>/…`; the proxy resolves the
agent's stored credential for that upstream and injects it. Upstreams:
`anthropic`, `openai`, `zen` (OpenCode Zen pay-as-you-go), `zengo` (OpenCode Zen
"go" subscription), and the MiniMax direct endpoints `minimax`,
`minimax-cn` (China), `minimax-anthropic`, `minimax-anthropic-cn` (China).

- **claude-code** — `ANTHROPIC_BASE_URL` = `<proxy>/claude-code/anthropic`,
  `ANTHROPIC_API_KEY` = `sandboxd-proxy-injected`. Works for both an API key and
  a Claude **subscription** (OAuth bearer + `anthropic-beta` are injected proxy-side).
- **opencode** — routed via an `OPENCODE_CONFIG` file that runtimed writes, which
  sends opencode's requests to the proxy with the dummy key. Which OpenCode Zen
  endpoint it uses is set by `SANDBOXD_OPENCODE_ZEN_PATH` — see
  [OpenCode Zen: subscription vs pay-as-you-go](#opencode-zen-subscription-vs-pay-as-you-go)
  below. (Implementation note: opencode's Zen provider ignores base-URL env vars
  and its Bun runtime rejects a bare hostname, so we can't just set a `*_BASE_URL`;
  the config file defines a custom `@ai-sdk/openai-compatible` provider pointed at
  the proxy's resolved **IP**, and the task's model is rewritten to `proxy/<id>`.)
- **codex** — parked: its ChatGPT-subscription backend is a WebSocket that can't be
  proxied yet, so codex is hidden from the run picker.

- **MiniMax** — a credential-only provider: connect a MiniMax API key in
  Settings → AI Agents (`POST /v1/agents/minimax/api-key`). MiniMax is not a
  task agent (no CLI, not in the run picker); its key is injected by the proxy
  for the MiniMax direct upstreams. The OpenCode opencode model dropdown exposes
  `MiniMax-M3` and `MiniMax-M2.7`; selecting one routes the task to the MiniMax
  OpenAI-compatible endpoint with the connected key (the China region is
  selected with `SANDBOXD_MINIMAX_REGION=cn_zh`, default `global_en`).

  | Region | OpenAI-compatible | Anthropic-compatible |
  |--------|-------------------|----------------------|
  | `global_en` *(default)* | `https://api.minimax.io/v1` | `https://api.minimax.io/anthropic` |
  | `cn_zh` | `https://api.minimaxi.com/v1` | `https://api.minimaxi.com/anthropic` |

  MiniMax model metadata (retained for operator reference): **MiniMax-M3** —
  1,000,000-token context, image and video input, adaptive or disabled thinking,
  pricing $0.60 / $2.40 / $0.12 per million input / output / cache-read tokens.
  **MiniMax-M2.7** — 204,800-token context, text input, always-on thinking,
  pricing $0.30 / $1.20 / $0.06 per million input / output / cache-read tokens.
  MiniMax endpoints authorize with `Authorization: Bearer <key>`.

**The real credential never appears in the sandbox filesystem or env** — verify
with `mount | grep agent-auth` (none) and `ls /run/agent-auth` (absent).

### OpenCode Zen: subscription vs pay-as-you-go

OpenCode Zen has **two gateways**, and the same key behaves differently on each.
`SANDBOXD_OPENCODE_ZEN_PATH` picks which one opencode uses:

| Value | Endpoint | Billing | Models |
|-------|----------|---------|--------|
| `zen` *(default)* | `opencode.ai/zen/v1` | Pay-as-you-go — needs a positive wallet balance | Full catalog: `claude-*`, `gpt-*`, `gemini-*`, plus the open models |
| `zengo` | `opencode.ai/zen/go/v1` | Included in the OpenCode **"go" subscription** — no balance needed | Open models only: GLM, Kimi, MiniMax, DeepSeek, Qwen, MiMo… |

**Which one do I want?**

- On the **"go" subscription** → set `zengo`. Your included models run without a
  balance. (This deployment is on the go plan, so `.env` sets `SANDBOXD_OPENCODE_ZEN_PATH=zengo`.)
- **Pre-paid a Zen wallet** and want Claude/GPT/Gemini through opencode → leave it
  `zen` (the default).

**Symptom of the wrong setting:** an opencode task fails with **`Insufficient
balance`** → you're on `zen` (pay-as-you-go) with an empty wallet; switch to
`zengo` (or top up). A task that fails with **`Model … is not supported`** → the
picked model isn't in that path's catalog (e.g. a `claude-*` model on `zengo`).

The console's opencode model dropdown should list models from whichever path you
set — go-subscription models (GLM/Kimi/…) for `zengo`.

### OpenCode free tier — works with no key (zero friction)

**opencode is usable out of the box with nothing connected.** Zen serves a set of
free models (ids ending `-free`, e.g. `big-pickle`, `deepseek-v4-flash-free`,
`mimo-v2.5-free`) that need **no API key**. When opencode has no connected
credential, the proxy forwards its requests to Zen **keyless** — it drops the
sandbox's dummy key and injects nothing — and always to the **`zen`** endpoint
where the free models live (even if the deployment pins `zengo`, whose
go-subscription catalog has no free models). The control plane defaults the
task's model to a free one so a fresh install can build immediately.

> Zen's API **requires a named model** — there is no keyless "auto" model, and
> only the `-free` models work without a key. That's why a free model must be
> named; it's not something opencode can pick on its own through the proxy.

- **No key** → free tier. The default free model is `big-pickle`; override with
  `SANDBOXD_OPENCODE_FREE_MODEL`.
- **Key connected** (Settings → AI Agents) → the proxy injects it and opencode
  gets the full paid catalog, exactly as before. A connected key always wins.

This is **opencode-only** — it's the one provider with a keyless free tier. Every
other agent (claude-code, codex) still returns a clear "connect it" error when
unconnected. See `internal/authproxy/proxy.go` (`credFor`) and
`internal/api/v1_tasks.go` (model precedence).

### Per-agent default model (optional)

Set a default model per agent in **Settings → AI Agents → Default model** (or via
`PATCH /v1/settings` `agents.default_models`). You supply the agent's real model
id (e.g. opencode `glm-5`, claude `sonnet`); it's used when a task doesn't specify
one. Stored durably, applied live. Model precedence for a task:

1. the task's own `model` (per request), then
2. the per-agent default (this setting), then
3. opencode's free-tier default (only when opencode has no key), then
4. runtimed's env/agent default (`SANDBOXD_OPENCODE_MODEL` / the CLI's own).

### Fallback: no proxy → mounted auth dir

If the proxy is disabled, the connected provider's opaque auth dir
(`<DataDir>/agent-auth/<provider>/`, outside any workspace) is bind-mounted
read-only at `/run/agent-auth/<provider>` and runtimed points the agent's `HOME`
there; an API-key connect instead injects the provider's one key var. This is the
legacy path — with the proxy on (the default), nothing is mounted or injected.

## Env scrub

The agent process env is scrubbed of secret-shaped variables (`*_KEY`,
`*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_CREDENTIALS`, and runtimed's own
`RUNTIMED_*`). So:

- An agent can never pick up a stray credential from the container env.
- **Injecting a key via the sandbox `env` no longer reaches the agent** — e.g.
  `ANTHROPIC_API_KEY` set at create time is dropped. Connect the provider
  instead (API-key connect re-injects it from the managed file).

Non-secret config (`PATH`, `HOME`, `LANG`, `*_MODEL`, `*_BASE_URL`, …) is kept.

## Agent context — platform prompt + per-app guide

So an agent understands its environment and doesn't break things, two context
layers are injected with **no change to your source**:

- **Platform system prompt** — a single committed
  [`control-plane/internal/agentprompt/prompt.md`](../control-plane/internal/agentprompt/prompt.md),
  embedded into both the control plane and `runtimed`. runtimed renders it with
  the sandbox's real port/health and appends it to every run — via
  `--append-system-prompt` for claude-code, and as a prompt preamble for
  opencode. It defines the guardrails: bind `0.0.0.0`, don't rewrite
  `sandbox.yaml` carelessly, don't touch `/run/agent-auth`, no destructive git
  on the main branch, verify on the loopback port before finishing. It is
  surfaced **read-only** as `agents.system_prompt` in `GET /v1/settings`
  (Console → Settings → Agent system prompt).
- **Per-app `AGENTS.md`** — the detected stack, upstream repo link, and how-to-run,
  written to `workspace/app/AGENTS.md` on runtime apply (git-ignored via
  `.git/info/exclude`) unless the repo already ships one. This is a **console**
  behavior on top of `/v1`, not a core write.

## What's guaranteed

Credentials are absent from: the workspace, snapshots (workspace tree only), the
container env / `docker inspect`, task results, events, and logs. For claude-code
subscriptions the token isn't even on the container filesystem — it lives only
behind the control-plane proxy.

## Running a task

Submit `POST /v1/sandboxes/{id}/tasks` with `{"prompt":"…","agent":"opencode","model":"opencode/glm-5"}`.
runtimed runs the CLI in the workspace (`--dangerously-skip-permissions`, since
the containment boundary is the throwaway sandbox, not the agent), streams events
over SSE (`/tasks/{taskId}/events`), and returns a final result. `model` maps to
the CLI's `--model`.

Defaults:

- **Agent** — `SANDBOXD_DEFAULT_AGENT` (default `opencode`) picks the agent for
  tasks that don't specify one.
- **Continue** — `continue` is a tri-state and **defaults to continuing** the
  sandbox's most recent agent session (`claude/opencode --continue`, codex
  `resume --last`). Omit it and runtimed continues when a prior session exists and
  starts fresh on the first task; send `true`/`false` to force the choice. Each
  sandbox is one workspace, so "most recent" is naturally per-sandbox.

## Configuration reference

Operator knobs for agent auth & task defaults (all optional; sensible defaults shown):

| Env var | Default | What it does |
| --- | --- | --- |
| `SANDBOXD_AGENT_PROXY_URL` | `http://sandboxd:9100` | In-network URL of the credential-injecting proxy. Set/empty toggles the proxy vs. legacy mounted-auth model. |
| `SANDBOXD_DEFAULT_AGENT` | `opencode` | Agent used for tasks that don't specify one. |
| `SANDBOXD_OPENCODE_ZEN_PATH` | `zen` | OpenCode Zen endpoint for opencode: `zen` (pay-as-you-go, full catalog) or `zengo` (the "go" subscription's models). See [OpenCode Zen: subscription vs pay-as-you-go](#opencode-zen-subscription-vs-pay-as-you-go). |
| `SANDBOXD_OPENCODE_MODEL` | *(unset)* | Global default `--model` for opencode tasks that don't pass one. |
| `SANDBOXD_MINIMAX_REGION` | `global_en` | MiniMax direct endpoint region for MiniMax models: `global_en` (`api.minimax.io`) or `cn_zh` (`api.minimaxi.com`). Requires a connected MiniMax API key. |

Per-task, `POST /tasks` also accepts `agent`, `model`, and `continue` (tri-state —
see [Running a task](#running-a-task)).

## App-scoped provider broker candidate (opt-in, not shipped in Desktop)

`internal/provideraccess` is an in-process building block for installed agents
such as OpenClaw. It starts no daemon/listener, has no Desktop dependencies, and
is enabled only by `SANDBOXD_PROVIDER_ACCESS_MODE=scoped`. Default `legacy` mode
keeps existing coding-agent behavior. It is ordinary MIT engine code, not a
commercial feature or a separate control-plane fork.

Scoped mode requires API authentication, a valid internal proxy URL and updated
control-plane **and runtimed** binaries. Bad mode/configuration or inability to
bind the proxy listener aborts startup; it does not silently fall back to shared
access. The workload listener has header/body read deadlines and hosts both the
installed-app broker and a grant-enforcing CLI proxy. Only then does
`GET /v1/settings` advertise `capabilities.scoped_provider_access=true`. This is
an API availability declaration, not evidence of native OS/agent compatibility.

The authenticated management API adds:

- `POST /v1/apps/{id}/provider-grants` with `provider: "anthropic"`, `config_key`
  and `ttl_seconds` (60–86400). The returned token is one-time disclosure with
  `Cache-Control: no-store`; `base_path` is relative to the internal proxy.
- `DELETE /v1/apps/{id}/provider-grants/{grantId}` for idempotent owner-scoped
  revocation. Neither operation is exposed on the workload listener.

There is no raw credential read endpoint and no grant-list endpoint that can
recover a token. The optional renewal API below can extend an unexpired delivered
lease without rotating its token. Scheduling is the trusted client's job; the
engine starts no renewal daemon. Never hand management API credentials to an
installed agent.

The initial provider is Anthropic **API keys only**. A trusted caller supplies
the authenticated owner's identity, app ID, app-config key and requested TTL to
`Broker.Issue`. The encrypted config must explicitly allow `runtime_access` or
`both`; plaintext config, `agent_access` alone, another owner's app, global
provider connections and subscription credentials do not qualify. The raw
256-bit delegated token is returned once. Only its SHA-256 digest is stored.

`Broker.ServeHTTP` accepts the delegated token as an SDK API-key header or bearer
header, not both. It exposes only these fixed-provider operations:

- `POST /apps/{app}/anthropic/v1/messages`
- `POST /apps/{app}/anthropic/v1/messages/count_tokens`
- `GET /apps/{app}/anthropic/v1/models`

It checks current app/config ownership, permission and expiration on every
request, decrypts the provider key inside the control plane, and injects it only
into the fixed HTTPS Anthropic destination. Caller cookies, forwarded headers,
credentials and arbitrary URLs are not forwarded. Encoded/noncanonical routes,
queries and ambiguous auth are rejected. Successful streams pass through; errors
and redirects become fixed errors. The HTTP transport ignores environment proxy
settings. Bodies are limited to 8 MiB, authorized concurrency to 16, and the
upstream exchange to ten minutes. This is not a spending budget or model policy.

Migration `0028_provider_grants.sql` stores grants and uses SQLite triggers to
revoke them atomically on config update/delete, app deletion or owner change.
Restoring an old permission or recreating a deleted record cannot revive the
token. A newly issued or renewed lease lasts at most 24 hours from that operation.
Repeated owner-authorized renewal can keep the same token valid longer; revoke
or replace it if compromise is suspected. Restart preserves unexpired grants;
explicit revocation is owner/app-scoped. Revocation prevents **new requests**,
not completion of an already authorized stream. A stolen token remains a bearer
capability for its one app/provider; it is not proof of container identity.

### Private delivery for installed-agent launchers

An authenticated controller can add `runtime_sandbox_id` to the existing grant
request. `capabilities.runtime_provider_delivery` advertises the control-plane
path; the runtime must separately advertise `scoped_provider_connection`.
The target must be the app's current **running** sandbox. This operation neither
wakes workloads nor invokes a model. It serializes with existing sandbox lifecycle
locks and rechecks ownership/consent/running binding atomically during issuance.

The response is `{id, expires_at, provider, runtime_sandbox_id, delivered:true}`,
**without the token**. The controller sends it directly over the existing runtime
Unix socket. The supervisor retains the connection only in memory. Its local
`GET /provider-connection` returns `{id, base_url, token, expires_at, booted_at}`
to an installed-agent launcher in that sandbox; this is not a public `/v1` route.
Delivery validates the operator-configured proxy, bounded token/route/expiry and
the exact supervisor boot timestamp. No file, subprocess argument or public
status field receives the token from the delivery implementation.

All processes under the sandbox UID can read or replace this local memory slot;
it is not an isolation boundary within a sandbox. Only the control-plane broker
can issue usable tokens. Agents can still disclose their own delegated capability,
and launchers must keep it out of project files, logs and preview URLs. This is
not a guarantee against an agent deliberately persisting or emitting it.

Migration 0030 binds delivered grants to sandbox lifecycle. Reconnection replaces
the sandbox's previous delivered grant in the same transaction. Stop, deletion
or app rebinding revokes it; original caller-returned grants retain their existing
semantics. Failed or ambiguous delivery attempts revoke the new grant using a
separate bounded context, even if the management caller disconnected. Failure to
confirm revocation returns `provider_revoke_pending`, never a success receipt.

Supervisor restart discards the memory slot. A new explicit delivery is required;
there is no automatic renewal or background daemon. An unobserved supervisor
crash does not itself change the database status: an already copied token remains
usable until revocation, replacement or its TTL. Stopping the sandbox via the
engine revokes it. Revocation denies new provider requests, not in-flight streams.
Memory delivery alone does not reload an already running agent's SDK config.

Tests cover real SQLite rotation and lifecycle triggers, wrong-owner/target,
stopped/busy/old runtime rejection, a real Unix socket, lost responses, sanitized
runtime errors, token-free receipts/status, expiry and boot-change rejection.
Consumer installer/launcher integration and renewal remain required.

### Non-disruptive delivered-connection renewal (development)

`capabilities.runtime_provider_renewal` advertises two additional management
operations. The selected supervisor must separately advertise
`scoped_provider_renewal`; older supervisors are rejected before any mutation.

- `GET /v1/apps/{id}/provider-connection` verifies the current running sandbox,
  ownership, config consent, database lease and supervisor boot/connection.
  Returns only `{id, expires_at, provider, runtime_sandbox_id, delivered:true}`
  with `Cache-Control: no-store`. It never starts a workload or reads a raw token.
- `POST /v1/apps/{id}/provider-connection/renew` takes the exact existing `id`,
  `runtime_sandbox_id` and `ttl_seconds` (60–86400). It extends that still-valid
  lease using an atomic ownership/permission/binding/expiry check, then updates
  the same in-memory supervisor connection. The token, ID, URL and stored token
  hash do not change. Existing revocation triggers remain authoritative.

This prevents a routine renewal from requiring an agent SDK credential reload
or process restart. A launcher must observe refreshed expiry for the same
connection instead of terminating at its original deadline. There is no new
schema, background worker, Electron dependency or default-mode change.

Renewal cannot revive expired, explicitly revoked, permission-changed, rotated,
stopped or rebound access. A supervisor restart loses its private connection
and requires explicit delivery again. Unknown or unconfirmed private renewal
revokes the extended lease under an independent timeout even if the management
request was cancelled; failure to confirm that revocation is reported as
`provider_revoke_pending`. Do not automatically issue replacement access after
these failures. Already-authorized model streams can still finish.

The existing same-sandbox Unix socket also exposes non-secret status and an
expiry-update operation. A workload can change its local expiry hint but cannot
change broker authorization: management credentials never enter the sandbox,
and every provider request still checks the database's expiry and consent.
Lease metadata is excluded from ordinary supervisor status. Cross-app/owner,
stale expiry, boot changes, malformed bodies, lost responses, cancellation and
revocation are covered by SQLite/Unix-socket tests. This development extension
is not yet in a published runtime bundle or connected to Desktop's scheduler.

The opt-in real OpenClaw probe also passed with a newly compiled `runtimed`
binary supplied via `SANDBOXD_OPENCLAW_RUNTIMED_BINARY` to the Desktop harness.
It delivers to the real supervisor, reads the connection over its Unix socket,
then completes two gateway boots and tool/stream cycles through the actual
broker. The helper puts its temporary agent configuration on container tmpfs,
not in the project. Model responses are synthetic and the management API is
tested separately; this is not a full consumer install or native OS test.

### Existing coding tasks in scoped mode

`v1SubmitTask` verifies the owning app before waking it and issues a separate
capability bound to its app, sandbox, selected agent and provider route. It passes
the token/upstream only in the internal Unix-socket runtime request; public task
JSON cannot select them and acceptance/status metadata does not include them.
An agent can read or emit its own delegated token; this boundary protects the
real provider credential, not the task token from its authorized holder.
The Claude adapter uses the delegated token
in its SDK environment. OpenCode uses it in its private temporary provider config
and environment; the controller-selected route wins over sandbox defaults. Real
provider credentials stay behind the existing proxy, including Claude OAuth.
Before issuance, the controller checks the supervisor's additive internal
`scoped_provider_tasks` declaration. A missing/old supervisor returns
`runtime_incompatible` before receiving a task or token; it is not silently
retried with the legacy dummy key.

Migration 0029 stores only task-token hashes. Task completion, sandbox stop/delete,
app deletion/owner change, rejected task start and explicit revocation invalidate
the ticket. TTL is the task timeout (default ten minutes, maximum 24 hours).
Unexpired tickets survive engine restart while the sandbox is still running.
The existing task watcher revokes on persisted terminal status; if that watcher
cannot persist a result, TTL remains the upper bound. In-flight provider requests
may finish after revocation. Tickets do not migrate a task across a stopped or
recreated sandbox.

`authproxy.NewScoped` checks authorization before credential lookup. Installed-app
grants, dummy keys and wrong-agent/provider task tokens are rejected on shared
CLI routes. Conversely, task tokens do not authorize installed-app routes. Both
paths constrain methods/paths and destinations, drop caller credentials/cookies,
bound bodies/concurrency, stream successful responses and sanitize error bodies.
The strict CLI path allows Anthropic's `beta=true` query but not arbitrary query
parameters. Error detail is intentionally reduced until safe provider diagnostics
are implemented. Default legacy proxy behavior remains unchanged.

CLI connections still use the existing engine-global credential store and the
existing engine-operator trust model. This does not add per-tenant ownership to
global provider connections, spending limits, or model-name restrictions. Installed
agent grants use the separate app-owned encrypted config store. A shared/multi-user
service needs a separate credential-ownership design before treating this as
multi-tenant provider isolation.

Integration/release requirements still outstanding:

- Legacy mode still has the old shared-proxy semantics. Do not add a second
  ungranted proxy or expose legacy credentials alongside scoped mode. The new
  gateway is unit/integration-tested, not yet tested with real CLI/provider
  traffic in a complete managed installation. Older runtimed binaries are
  refused by the scoped task preflight and must be updated explicitly.
- Integrate private runtime delivery into the installed-agent launcher and complete
  automatic renewal and preview authentication.
  Never place engine management tokens in agent containers or grant tokens in
  browser preview URLs. No workload may issue its own grant.
- Add consumer provider-selection/consent, model compatibility, billing/error
  UX, expired-record cleanup and native restart/recovery tests. A fixed proxy is
  not an approval broker for an agent's other tools or network access.
- Reconcile migration numbering with unpublished engine candidates before
  integration. 0025–0027 are reserved by the existing Desktop runtime candidate;
  the current migration runner supports gaps and applies 0028/0029 on the clean base.

Tests use real SQLite and encrypted synthetic credentials, plus a local HTTP
streaming server. They cover ownership, permission changes, expiry, persistence,
revocation, cross-app denial, route/header filtering, redirects, size/concurrency
limits, corrupt ciphertext and client cancellation. Additional tests exercise the
combined gateway, task submission over a real Unix socket to a simulated runtimed,
internal token delivery, public-response redaction and revocation on task result
or submission rejection. CLI adapter checks are fixtures, not real inference.
Run from `control-plane`:

```bash
go test ./...
go test -race ./internal/provideraccess ./internal/store ./internal/authproxy ./internal/api ./cmd/runtimed
```

### Opt-in real agent protocol probes (2026-10-15)

`scripts/probe-scoped-cli.mjs` compiles `TestLiveScopedCLI` and runs it in a
fresh non-root, read-only-rootfs container with networking disabled, no host
mounts and no provider credentials. Supply the exact local runtime image ID:

```bash
SANDBOXD_SCOPED_CLI_PROBE=1 \
SANDBOXD_PROBE_RUNTIME_IMAGE=sha256:6ce923085308626fcc23586acc6bd29fef237f7b16220945cae49debd10841b6 \
SANDBOXD_PROBE_AGENT=opencode node scripts/probe-scoped-cli.mjs
```

Run from the repository root with Go installed (or set `SANDBOXD_PROBE_GO`).
OpenCode 1.19.0 passed actual CLI file-write/tool-result/streaming and post-revoke
denial through the scoped gateway on Linux ARM64. Model responses are synthetic;
there is no provider authentication or inference validation. Claude Code is
absent from that image (manifest: install required); its probe did not pass.

`TestLiveOpenClawScoped` is a second opt-in integration entry point, compiled
with `go test -c ./internal/provideraccess`. The separate Desktop repository's
`probe-openclaw-runtime.mjs` accepts that external test binary and migrations
via `SANDBOXD_OPENCLAW_BROKER_BINARY` and
`SANDBOXD_OPENCLAW_BROKER_MIGRATIONS`; nothing is copied into the product.
OpenClaw 2026.10.3 with private Node 24.16.0 passed two actual gateway boots,
authenticated/unauthenticated API checks, real file-write tools and streamed
synthetic replies through the app broker, followed by grant revocation denial.
The provider transport is replaced only inside the Go test; production still
uses the fixed HTTPS destination. Dependency installation precedes network
disconnection; agent execution is offline, in disposable owned storage.

These probes do not test management API installation, automatic grant renewal,
browser pairing, paid model inference, native Windows/macOS or certify security.
Production and the published runtime bundle are unchanged.
