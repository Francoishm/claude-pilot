'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { Notifier } = require('../src/notify');

function fakeFetch() {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, body: JSON.parse(opts.body) });
    return { status: 204 };
  };
  fn.calls = calls;
  return fn;
}

test('une alerte part sur le webhook Discord', async () => {
  const fetchImpl = fakeFetch();
  const n = new Notifier({ webhookUrl: 'https://example.invalid/hook', desktop: false, fetchImpl });
  assert.equal(await n.send('full:energy', 'Torn — energy pleine', '150/150'), true);
  assert.equal(fetchImpl.calls.length, 1);
  assert.match(fetchImpl.calls[0].body.content, /energy pleine/);
});

test('le cooldown etouffe les alertes repetees', async () => {
  const fetchImpl = fakeFetch();
  const n = new Notifier({ webhookUrl: 'https://example.invalid/hook', desktop: false, fetchImpl, cooldownMs: 1000 });
  assert.equal(await n.send('k', 'A', '', 0), true);
  assert.equal(await n.send('k', 'A', '', 500), false);
  assert.equal(await n.send('k', 'A', '', 1500), true);
  assert.equal(fetchImpl.calls.length, 2);
});

test('un webhook en panne ne fait pas echouer l’alerte', async () => {
  const failing = async () => {
    throw new Error('reseau coupe');
  };
  const n = new Notifier({ webhookUrl: 'https://example.invalid/hook', desktop: false, fetchImpl: failing });
  assert.equal(await n.send('k', 'A'), true);
});

test('sans webhook ni bureau, l’alerte reste silencieuse mais comptabilisee', async () => {
  const n = new Notifier({ webhookUrl: null, desktop: false });
  assert.equal(await n.send('k', 'A'), true);
  assert.equal(await n.send('k', 'A'), false);
});
