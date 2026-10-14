import test from 'node:test';
import assert from 'node:assert/strict';
import { imageReceipt, bundleManifest, exportArguments } from './runtime-bundle.mjs';
const image = { Os: 'linux', Architecture: 'arm64', Id: 'sha256:' + 'a'.repeat(64), Size: 100 };
const images = Object.fromEntries(['engine', 'runtime', 'edge'].map(role => [role, imageReceipt(image, 'arm64')]));
const archive = { name: 'sandboxd-runtime-linux-arm64.tar.gz', bytes: 10, sha256: 'b'.repeat(64) };
test('exports IDs only, so loading does not overwrite existing image tags', () => {
  assert.deepEqual(exportArguments(images), ['image', 'save', image.Id, image.Id, image.Id]);
  assert.throws(() => exportArguments({ ...images, engine: { id: 'sandboxd:latest' } }));
});
test('manifest binds image IDs, architecture, commit and compressed bytes without overstating tests', () => {
  const result = bundleManifest('c'.repeat(40), 'arm64', images, archive);
  assert.equal(result.images.engine.id, image.Id);
  assert.equal(result.verification.realProviderInference, false);
  assert.equal(result.agents['claude-code'], 'install-required');
});
test('rejects wrong native architecture, missing image, mutable revision and oversize assets', () => {
  assert.throws(() => imageReceipt(image, 'amd64'));
  assert.throws(() => bundleManifest('main', 'arm64', images, archive));
  assert.throws(() => bundleManifest('c'.repeat(40), 'arm64', {}, archive));
  assert.throws(() => bundleManifest('c'.repeat(40), 'arm64', images, { ...archive, bytes: 2 * 1024 ** 3 }));
});
