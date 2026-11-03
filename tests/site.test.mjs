import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Guards the things that rot silently in a static site: a README that links a
 * screenshot nobody committed, an import typo that only fails once deployed,
 * and — the important one here — a "nothing leaves the browser" promise that
 * the code stops keeping.
 *
 * The header logic itself is tested in headers.test.mjs.
 */

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (...parts) => fs.readFileSync(path.join(ROOT, ...parts), 'utf8');
const exists = (...parts) => fs.existsSync(path.join(ROOT, ...parts));

const html = read('index.html');
const app = read('assets', 'app.js');
const headers = read('assets', 'headers.js');
const samples = read('assets', 'samples.js');
const css = read('assets', 'style.css');

let readme = '';
try {
  readme = read('README.md');
} catch {
  // The README test below reports this as a failure with a useful message.
}

/** Anything that is not a remote URL, an anchor or an inline data URI. */
const isLocalRef = (ref) => ref && !/^(https?:|mailto:|data:|#|\/\/)/i.test(ref);

test('every local src/href in index.html exists on disk', () => {
  const refs = [...html.matchAll(/(?:src|href)="([^"]+)"/g)]
    .map((match) => match[1])
    .filter(isLocalRef)
    .map((ref) => ref.split('?')[0].split('#')[0])
    .filter(Boolean);

  assert.ok(refs.length >= 3, 'expected stylesheet and script references');

  for (const ref of refs) {
    assert.equal(exists(ref), true, `index.html references missing file: ${ref}`);
  }
});

test('every relative import resolves to a real file', () => {
  const imports = [...app.matchAll(/from\s+'(\.[^']+)'/g)].map((match) => match[1]);
  assert.ok(imports.length >= 2, 'app.js should import headers.js and samples.js');

  for (const specifier of imports) {
    const target = path.join('assets', specifier);
    assert.equal(exists(target), true, `app.js imports missing file: ${target}`);
  }
});

test('README exists and every screenshot it points at was committed', () => {
  assert.ok(readme.length > 0, 'README.md is missing');
  const refs = [...readme.matchAll(/docs\/screenshots\/[A-Za-z0-9._-]+\.png/g)].map((m) => m[0]);
  assert.ok(refs.length > 0, 'README should show at least one real screenshot');

  for (const ref of new Set(refs)) {
    assert.equal(exists(ref), true, `README references missing image: ${ref}`);
  }
});

test('index.html has the metadata a shared link needs', () => {
  assert.match(html, /<html lang="[a-z]{2}/i);
  assert.match(html, /<meta charset="utf-8">/i);
  assert.match(html, /name="viewport"/i);
  assert.match(html, /<title>[^<]{10,}<\/title>/i);
  assert.match(html, /name="description" content="[^"]{50,}"/i);
  assert.match(html, /rel="icon"/i);
});

test('the paste box has a real label, not just a placeholder', () => {
  assert.match(html, /<label[^>]*for="raw"/, 'textarea #raw has no <label>');
  assert.match(html, /id="raw"/);
  assert.match(html, /aria-live="polite"/, 'the result panel should announce updates');
});

test('the page loads nothing from a third party', () => {
  // Fonts and scripts from a CDN would be a network request the page denies making.
  const remote = [...html.matchAll(/<(?:script|link)\b[^>]*(?:src|href)="(https?:[^"]+)"/g)].map(
    (match) => match[1]
  );
  assert.deepEqual(remote, [], 'index.html must not load remote scripts or styles');

  for (const [name, source] of [['app.js', app], ['headers.js', headers], ['samples.js', samples]]) {
    assert.equal(/from\s+'https?:/.test(source), false, `${name} imports from a CDN`);
  }
});

test('the page keeps its promise: no code path can send the pasted headers anywhere', () => {
  // The intro and footer both say nothing leaves the browser. A single fetch,
  // XHR, socket, beacon or dynamically created image would make that a lie.
  const forbidden = [
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    /\bWebSocket\b/,
    /\bsendBeacon\b/,
    /\bnew\s+Image\s*\(/,
    /\bnavigator\.sendBeacon\b/,
  ];

  for (const [name, source] of [['app.js', app], ['headers.js', headers], ['samples.js', samples]]) {
    for (const pattern of forbidden) {
      assert.equal(pattern.test(source), false, `${name} contains ${pattern}: the page claims no network`);
    }
  }
});

test('the two samples are synthetic: documentation IPs and reserved domains only', () => {
  // If somebody ever pastes a real email into samples.js, this fails the build.
  const ipv4 = samples.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
  assert.ok(ipv4.length > 0, 'expected IPs in the sample headers');

  const isSafeIp = (ip) => {
    const [a, b] = ip.split('.').map(Number);
    const documentation = a === 192 && b === 0 && ip.startsWith('192.0.2.');
    const doc2 = ip.startsWith('198.51.100.');
    const doc3 = ip.startsWith('203.0.113.');
    const privateRange = a === 10 || a === 127 || (a === 192 && b === 168);
    return documentation || doc2 || doc3 || privateRange;
  };

  for (const ip of new Set(ipv4)) {
    assert.equal(isSafeIp(ip), true, `sample uses a routable public IP: ${ip}`);
  }

  const domains = [...samples.matchAll(/@([a-z0-9.-]+\.[a-z]{2,})/gi)].map((m) => m[1].toLowerCase());
  assert.ok(domains.length > 0, 'expected email domains in the samples');

  const reservedSuffixes = ['.example', '.example.org', '.example.com', '.test', '.invalid', '.localhost'];
  for (const domain of new Set(domains)) {
    const reserved = reservedSuffixes.some((suffix) => domain === suffix.slice(1) || domain.endsWith(suffix));
    const invented = domain.endsWith('.co.za') || domain.endsWith('.example');
    assert.equal(
      reserved || invented,
      true,
      `sample uses a domain that could belong to someone: ${domain}`
    );
  }
});

test('no debugging leftovers in the shipped JavaScript', () => {
  for (const [name, source] of [['app.js', app], ['headers.js', headers], ['samples.js', samples]]) {
    assert.equal(/debugger;/.test(source), false, `${name} contains a debugger statement`);
    assert.equal(/console\.(log|debug|trace)\(/.test(source), false, `${name} logs to the console`);
  }
});

test('the stylesheet defines the colour variables the markup relies on', () => {
  for (const token of ['--paper', '--card', '--ink', '--muted', '--bad', '--warn', '--ok', '--info']) {
    assert.match(css, new RegExp(`${token}:`), `style.css is missing ${token}`);
  }

  assert.match(css, /prefers-reduced-motion/, 'style.css should respect reduced motion');
});

test('deep links are documented where they are implemented', () => {
  assert.match(app, /URLSearchParams\(location\.search\)\.get\('sample'\)/);
  assert.match(html, /id="how"|id="limits"/i);
});

test('the README documents how to run, test and read the limits', () => {
  assert.match(readme, /node --test/);
  assert.match(readme, /## Quick start/i);
  assert.match(readme, /## Known limitations/i);
  assert.match(readme, /MIT/);
  assert.match(readme, /Nothing leaves the browser|nothing leaves the browser/i);
});
