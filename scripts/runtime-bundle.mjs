import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, stat, writeFile, copyFile } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { createGzip } from 'node:zlib';
import { pathToFileURL } from 'node:url';
import { resolve, join } from 'node:path';

export function imageReceipt(image, architecture) {
  assert(image?.Os === 'linux' && image.Architecture === architecture, 'Wrong image platform');
  assert.match(image.Id, /^sha256:[a-f0-9]{64}$/);
  assert(Number.isSafeInteger(image.Size) && image.Size > 0, 'Invalid image size');
  return { id: image.Id, bytes: image.Size };
}
export function exportArguments(images) {
  const ids = ['engine', 'runtime', 'edge'].map(role => images[role]?.id);
  for (const id of ids) assert.match(id, /^sha256:[a-f0-9]{64}$/);
  // Saving by ID omits RepoTags: loading must never move an existing user's tag.
  return ['image', 'save', ...ids];
}
export function bundleManifest(source, architecture, images, archive) {
  assert.match(source, /^[a-f0-9]{40}$/);
  assert(['amd64', 'arm64'].includes(architecture));
  for (const role of ['engine', 'runtime', 'edge']) {
    assert.match(images[role]?.id, /^sha256:[a-f0-9]{64}$/);
    assert(Number.isSafeInteger(images[role].bytes) && images[role].bytes > 0);
  }
  assert.equal(archive.name, `sandboxd-runtime-linux-${architecture}.tar.gz`);
  assert.match(archive.sha256, /^[a-f0-9]{64}$/);
  assert(Number.isSafeInteger(archive.bytes) && archive.bytes > 0 && archive.bytes < 2 * 1024 ** 3);
  return { schema: 1, source, os: 'linux', architecture, images, archive,
    agents: { opencode: 'installed-unverified-auth', codex: 'installed-unverified-auth', 'claude-code': 'install-required', pi: 'install-required' },
    verification: { linuxSandboxLifecycle: true, nativeDesktop: false, realProviderInference: false } };
}
async function build() {
  const source = process.env.SOURCE_SHA;
  const architecture = process.env.TARGET_ARCH;
  assert.match(source || '', /^[a-f0-9]{40}$/);
  assert(['amd64', 'arm64'].includes(architecture));
  const tags = { engine: `sandboxd-control-plane:runtime-${source}`, runtime: `sandboxd-base:runtime-${source}`, edge: `sandboxd-edge:runtime-${source}` };
  const images = Object.fromEntries(Object.entries(tags).map(([role, tag]) => [role,
    imageReceipt(JSON.parse(execFileSync('docker', ['image', 'inspect', tag], { encoding: 'utf8' }))[0], architecture)]));
  const directory = resolve('runtime-dist'); await mkdir(directory);
  const name = `sandboxd-runtime-linux-${architecture}.tar.gz`;
  const archivePath = join(directory, name);
  const save = spawn('docker', exportArguments(images), { stdio: ['ignore', 'pipe', 'inherit'] });
  const exited = new Promise((resolve, reject) => { save.on('error', reject); save.on('exit', code => code === 0 ? resolve() : reject(Error('Image export failed'))); });
  await Promise.all([pipeline(save.stdout, createGzip({ level: 3 }), createWriteStream(archivePath, { flags: 'wx' })), exited]);
  const saved = JSON.parse(execFileSync('tar', ['-xOf', archivePath, 'manifest.json'], { encoding: 'utf8', maxBuffer: 1024 * 1024 }));
  assert(saved.length === 3 && saved.every(image => !image.RepoTags?.length), 'Bundle must not replace existing image tags');
  const hash = createHash('sha256'); for await (const chunk of createReadStream(archivePath)) hash.update(chunk);
  const manifest = bundleManifest(source, architecture, images, { name, bytes: (await stat(archivePath)).size, sha256: hash.digest('hex') });
  await writeFile(join(directory, `manifest-linux-${architecture}.json`), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  await writeFile(join(directory, `SHA256SUMS-linux-${architecture}`), `${manifest.archive.sha256}  ${name}\n`, { flag: 'wx' });
  await copyFile('LICENSE', join(directory, 'LICENSE'));
  console.log(`Prepared ${architecture} runtime bundle; native Desktop and provider authentication remain unverified.`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await build();
