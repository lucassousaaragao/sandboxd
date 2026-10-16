// Opt-in real Linux API/kernel lifecycle check; no model, production or host folders.
// Requires a separately built test-labelled engine and an immutable runtime image.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

assert.equal(process.platform, 'linux');
assert.equal(process.env.SANDBOXD_RESOURCE_LIMITS_LIVE, '1');
const engine = process.env.SANDBOXD_RESOURCE_TEST_ENGINE;
const runtime = process.env.SANDBOXD_RESOURCE_TEST_RUNTIME;
for (const image of [engine, runtime]) assert.match(image || '', /^sha256:[a-f0-9]{64}$/);
const id = randomBytes(5).toString('hex'), name = 'sdl-' + id, label = 'io.sandboxd.resource-limits-run';
const token = randomBytes(32).toString('hex');
const env = { PATH: '/usr/bin:/bin' };
const docker = (args, secret = false) => execFileSync('/usr/bin/docker', ['--host', 'unix:///var/run/docker.sock', ...args], {
  env: secret ? { ...env, SANDBOXD_API_TOKENS: 'test=' + token } : env,
  encoding: 'utf8', timeout: 120000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
}).trim();
const inspect = target => JSON.parse(docker(['inspect', target]))[0];
assert.equal(JSON.parse(docker(['image', 'inspect', engine]))[0].Config.Labels['io.sandboxd.resource-limits-test'], 'true');
const info = JSON.parse(docker(['info', '--format', '{"os":{{json .OSType}},"arch":{{json .Architecture}}}']));
assert.equal(info.os, 'linux');
for (const image of [engine, runtime]) {
  const found = JSON.parse(docker(['image', 'inspect', image]))[0];
  assert.equal(found.Os, 'linux');
  assert.equal(found.Architecture, ['aarch64','arm64'].includes(info.arch) ? 'arm64' : 'amd64');
}
let origin, appId, volumeCreated = false, networkCreated = false, started = false, clean = false;
const request = async (path, method = 'GET', body, status = 200, raw = false) => {
  const response = await fetch(origin + path, { method, headers: { Authorization: 'Bearer ' + token,
    'Content-Type': raw ? 'text/plain' : 'application/json' }, body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
    signal: AbortSignal.timeout(60000) });
  assert.equal(response.status, status, 'API status at ' + path);
  if (status === 204) return;
  return raw ? response.text() : response.json();
};
try {
  // Random resources are never adopted; successful creation is tracked before cleanup.
  assert(!docker(['volume', 'ls', '--format', '{{.Name}}']).split('\n').includes(name));
  docker(['volume','create','--label',label+'='+id,name]); volumeCreated = true;
  const volume = JSON.parse(docker(['volume','inspect',name]))[0];
  assert.equal(volume.Labels[label], id); assert.equal(volume.Driver, 'local');
  const data = volume.Mountpoint;
  assert.match(data, /^\/var\/lib\/docker\/volumes\/sdl-[a-f0-9]{10}\/_data$/);
  docker(['network','create','--label',label+'='+id,name]); networkCreated = true;
  docker(['run','-d','--pull=never','--name',name,'--label',label+'='+id,'--network',name,'--userns=host',
    '--cpus=1','--memory=512m','--memory-swap=512m','--pids-limit=128','-p','127.0.0.1::9000',
    '--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
    '--mount',`type=volume,src=${name},dst=${data},volume-nocopy`,
    '-e','SANDBOXD_API_TOKENS','-e','SANDBOXD_API_AUTH_DISABLED=false','-e','SANDBOXD_TELEMETRY=off',
    '-e','SANDBOXD_DATA_DIR='+data,'-e','SANDBOXD_LOG_DIR='+data+'/log','-e','SANDBOXD_NETWORK='+name,
    '-e','SANDBOXD_IMAGE='+runtime,'-e','SANDBOXD_IDLE_THRESHOLD_SECONDS=3600',
    '-e','SANDBOXD_SANDBOX_MEMORY_MIB=2048','-e','SANDBOXD_SANDBOX_CPU_MILLICORES=1000',
    '-e','SANDBOXD_SANDBOX_PIDS_LIMIT=256',engine],true); started = true;
  const port = inspect(name).NetworkSettings.Ports['9000/tcp'];
  assert.equal(port.length,1); assert.equal(port[0].HostIp,'127.0.0.1');
  origin = 'http://127.0.0.1:'+port[0].HostPort;
  let ready = false;
  for(let n=0;n<30;n++) {
    try { ready = (await fetch(origin+'/readyz',{signal:AbortSignal.timeout(1000)})).ok; } catch {}
    if(ready)break; await delay(1000);
  }
  assert(ready,'Fresh test engine did not become ready');
  assert.equal((await fetch(origin+'/v1/apps',{signal:AbortSignal.timeout(2000)})).status,401);
  const settings=await request('/v1/settings');
  assert.equal(settings.capabilities.runtime_resource_limits,true);
  assert.deepEqual(settings.runtime.resource_limits,{memory_mib:2048,cpu_millicores:1000,pids:256});
  const app = await request('/v1/apps','POST',{name:'Disposable resource lifecycle',tags:[label+':'+id]},201);
  assert.match(app.id,/^[0-9A-HJKMNP-TV-Z]{26}$/); appId=app.id;
  const sandbox=await request('/v1/apps/'+appId+'/sandbox','POST',{template:'blank'},201);
  assert.match(sandbox.id,/^[0-9A-HJKMNP-TV-Z]{26}$/);const container='s-'+sandbox.id;
  const ownedSandbox=()=>{const found=inspect(container);assert.equal(found.Config.Labels['sandboxd.managed'],'true');
    assert.deepEqual(Object.keys(found.NetworkSettings.Networks),[name]); assert.equal(found.Config.Image,runtime);return found;};
  const checkLimits=()=>{
    const found=ownedSandbox();const h=found.HostConfig;
    assert.equal(h.Memory,2147483648);assert.equal(h.MemorySwap,h.Memory);assert.equal(h.NanoCpus,1e9);assert.equal(h.PidsLimit,256);
    assert.equal(docker(['exec',container,'cat','/sys/fs/cgroup/memory.max']),'2147483648');
    assert.equal(docker(['exec',container,'cat','/sys/fs/cgroup/pids.max']),'256');
    const [quota,period]=docker(['exec',container,'cat','/sys/fs/cgroup/cpu.max']).split(/\s+/).map(Number);assert.equal(quota/period,1);
    return found.Id;
  };
  const initial=checkLimits(),marker='retain workspace across resource-policy recreation\n';
  await request('/v1/sandboxes/'+sandbox.id+'/files?path=budget-marker.txt','PUT',marker,200,true);
  await request('/v1/sandboxes/'+sandbox.id+'/start','POST',{});assert.equal(ownedSandbox().Id,initial);
  await request('/v1/sandboxes/'+sandbox.id+'/stop','POST',{});assert.equal(ownedSandbox().State.Running,false);
  docker(['update','--memory=1536m','--memory-swap=1536m','--cpus=0.5','--pids-limit=128',container]);
  await request('/v1/sandboxes/'+sandbox.id+'/start','POST',{});
  const replacement=checkLimits();assert.notEqual(replacement,initial);
  assert.equal(await request('/v1/sandboxes/'+sandbox.id+'/files/content?path=budget-marker.txt','GET',undefined,200,true),marker);
  await request('/v1/sandboxes/'+sandbox.id+'/stop','POST',{});
  await request('/v1/sandboxes/'+sandbox.id+'/start','POST',{});assert.equal(checkLimits(),replacement);
  console.log('Real API and Linux cgroup memory/CPU/PID limits passed; stopped-policy drift recreated only the container and retained workspace bytes.');
} finally {
  try {
    if(appId)await request('/v1/apps/'+appId,'DELETE',undefined,204);
    if(started)assert.deepEqual((await request('/v1/apps')).apps,[]);
    clean=true;
  } finally {
    if(started){assert.equal(inspect(name).Config.Labels[label],id);docker(['stop',name]);if(clean)docker(['rm',name]);}
    if(clean&&networkCreated){const found=JSON.parse(docker(['network','inspect',name]))[0];assert.equal(found.Labels[label],id);
      assert.equal(Object.keys(found.Containers||{}).length,0);docker(['network','rm',name]);}
    if(clean&&volumeCreated){assert.equal(JSON.parse(docker(['volume','inspect',name]))[0].Labels[label],id);docker(['volume','rm',name]);}
    console.log(clean?'Removed this run’s disposable infrastructure and project storage.':'Unconfirmed cleanup: retained owned resources '+name+'; inspect before removal.');
  }
}
