// Real CLI + scoped Go gateway compatibility, no paid inference or host access.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

assert.equal(process.env.SANDBOXD_SCOPED_CLI_PROBE, '1', 'Explicit opt-in required');
assert.equal(process.platform, 'linux');
const image = process.env.SANDBOXD_PROBE_RUNTIME_IMAGE;
const agent = process.env.SANDBOXD_PROBE_AGENT || 'opencode';
assert(['opencode', 'claude-code'].includes(agent));
assert.match(image ?? '', /^sha256:[a-f0-9]{64}$/, 'Supply the exact local runtime image ID');
const root = fileURLToPath(new URL('../', import.meta.url));
const execute = promisify(execFile);
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => ['HOME', 'PATH', 'LANG', 'TMPDIR'].includes(key)));
const run = async (command, args, options = {}) => (await execute(command, args, {
  env, encoding: 'utf8', timeout: 180_000, maxBuffer: 128 * 1024, ...options,
})).stdout.trim();
const docker = args => run('/usr/bin/docker', ['--host', 'unix:///var/run/docker.sock', ...args]);
const meta = JSON.parse(await docker(['image', 'inspect', image, '--format', '{{json .}}']));
assert.equal(meta.Id, image); assert.equal(meta.Os, 'linux'); assert(!meta.Config.Volumes);
assert.equal(meta.Architecture, process.arch === 'x64' ? 'amd64' : process.arch);
const staging = await mkdtemp(join(tmpdir(), 'sandboxd-scoped-cli-'));
const name = `sandboxd-scoped-cli-${randomBytes(6).toString('hex')}`, volume = `${name}-home`;
const label = 'io.sandboxd.scoped-cli-probe';
let storage = false, created = false;
try {
  console.log('Compiling opt-in Go integration test for the native Linux architecture.');
  await run(process.env.SANDBOXD_PROBE_GO || 'go', ['test', '-p', '2', '-c', '-o', join(staging, 'probe.test'), './internal/authproxy'], {
    cwd: join(root, 'control-plane'), env: { ...env, GOMAXPROCS: '2' },
  });
  assert.equal(await docker(['volume', 'ls', '--filter', `name=^${volume}$`, '--format', '{{.Name}}']), '');
  await docker(['volume', 'create', '--label', `${label}=${name}`, volume]); storage = true;
  await docker(['create', '--name', name, '--label', `${label}=${name}`, '--network', 'none', '--read-only',
    '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--cpus', '1', '--memory', '2g', '--memory-swap', '2g', '--pids-limit', '128',
    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=128m', '--mount', `type=volume,src=${volume},dst=/home/sandbox`,
    '--entrypoint', '/usr/bin/sleep', image, 'infinity']); created = true;
  await docker(['cp', join(staging, 'probe.test'), `${name}:/home/sandbox/probe.test`]);
  await docker(['cp', join(root, 'control-plane/migrations'), `${name}:/home/sandbox/probe-migrations`]);
  await docker(['start', name]);
  const state = JSON.parse(await docker(['inspect', name, '--format', '{{json .}}']));
  assert.deepEqual(Object.keys(state.NetworkSettings.Networks), ['none']);
  assert.equal(state.HostConfig.ReadonlyRootfs, true); assert.equal(state.Config.User, '1000:1000');
  assert.deepEqual(state.Mounts.map(m => [m.Type, m.Name, m.Destination]), [['volume', volume, '/home/sandbox']]);
  console.log('Executing real installed CLI with synthetic model responses, offline and without host mounts.');
  console.log(await docker(['exec', '--env', 'SANDBOXD_LIVE_SCOPED_CLI=1',
    '--env', `SANDBOXD_LIVE_AGENT=${agent}`,
    '--env', 'SANDBOXD_LIVE_MIGRATIONS=/home/sandbox/probe-migrations', name,
    '/home/sandbox/probe.test', '-test.run', '^TestLiveScopedCLI$', '-test.v', '-test.timeout', '150s']));
} finally {
  if (created) {
    assert.equal(await docker(['inspect', name, '--format', `{{index .Config.Labels "${label}"}}`]), name);
    await docker(['rm', '--force', name]);
  }
  if (storage) {
    assert.equal(await docker(['volume', 'inspect', volume, '--format', `{{index .Labels "${label}"}}`]), name);
    await docker(['volume', 'rm', volume]);
  }
  await rm(staging, { recursive: true, force: true });
  console.log('Removed only this invocation’s container, test volume and generated test binary.');
}
