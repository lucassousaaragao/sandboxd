import assert from 'node:assert/strict';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { bundleManifest } from './runtime-bundle.mjs';

const directory = resolve(process.argv[2]);
assert.match(process.env.SOURCE_SHA || '', /^[a-f0-9]{40}$/);
for (const arch of ['amd64', 'arm64']) {
  const manifest = JSON.parse(await readFile(join(directory, `manifest-linux-${arch}.json`), 'utf8'));
  assert.equal(manifest.source, process.env.SOURCE_SHA);
  assert.equal(manifest.architecture, arch);
  assert.deepEqual(manifest, bundleManifest(manifest.source, arch, manifest.images, manifest.archive));
  const file = join(directory, manifest.archive.name);
  assert.equal((await stat(file)).size, manifest.archive.bytes);
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  assert.equal(hash.digest('hex'), manifest.archive.sha256);
  assert.equal(await readFile(join(directory, `SHA256SUMS-linux-${arch}`), 'utf8'), `${manifest.archive.sha256}  ${manifest.archive.name}\n`);
}
assert.equal(await readFile(join(directory, 'LICENSE'), 'utf8'), await readFile('LICENSE', 'utf8'));
console.log('Both native runtime bundles match their committed source and checksums.');
