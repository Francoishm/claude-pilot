'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { buildSnapshot, normalizeBar } = require('../src/snapshot');

const RAW = {
  player_id: 42,
  name: 'Tester',
  level: 15,
  status: { state: 'Okay', description: 'Okay', until: 0 },
  server_time: 1700000000,
  energy: { current: 140, maximum: 150, increment: 5, interval: 600, ticktime: 120, fulltime: 1320 },
  nerve: { current: 22, maximum: 22, increment: 1, interval: 300, ticktime: 60, fulltime: 0 },
  happy: { current: 500, maximum: 4000, increment: 5, interval: 900, ticktime: 400, fulltime: 90000 },
  life: { current: 1000, maximum: 1000, increment: 100, interval: 300, ticktime: 0, fulltime: 0 },
  cooldowns: { drug: 0, medical: 120, booster: 3600 },
  travel: { destination: 'Torn', time_left: 0 },
  refills: { energy_refill_used: false, nerve_refill_used: true, token_refill_used: true },
  education: { education_current: 12, education_timeleft: 5000 },
  money_onhand: 12345,
  points: 20,
};

test('buildSnapshot normalise les barres a la racine', () => {
  const s = buildSnapshot(RAW, 1000);
  assert.equal(s.bars.energy.current, 140);
  assert.equal(s.bars.energy.isFull, false);
  assert.equal(s.bars.nerve.isFull, true);
  assert.equal(s.bars.nerve.fullIn, 0);
  assert.ok(Math.abs(s.bars.energy.ratio - 140 / 150) < 1e-9);
});

test('buildSnapshot accepte aussi les barres imbriquees sous `bars`', () => {
  const s = buildSnapshot({ bars: { energy: RAW.energy } }, 1000);
  assert.equal(s.bars.energy.current, 140);
});

test('buildSnapshot expose joueur, cooldowns et refills', () => {
  const s = buildSnapshot(RAW, 1000);
  assert.equal(s.player.level, 15);
  assert.equal(s.player.state, 'Okay');
  assert.equal(s.cooldowns.medical, 120);
  assert.equal(s.refills.energyUsed, false);
  assert.equal(s.refills.nerveUsed, true);
  assert.equal(s.travel.inFlight, false);
  assert.equal(s.fetchedAt, 1000);
});

test('buildSnapshot survit a un payload partiel', () => {
  const s = buildSnapshot({}, 1000);
  assert.deepEqual(s.bars, {});
  assert.equal(s.player.level, null);
  assert.equal(s.travel.inFlight, false);
});

test('normalizeBar calcule fulltime quand l’API ne le fournit pas', () => {
  const bar = normalizeBar('energy', { current: 145, maximum: 150, increment: 5, interval: 600, ticktime: 600 });
  assert.equal(bar.fullIn, 600);
});

test('normalizeBar rejette une barre sans valeurs exploitables', () => {
  assert.equal(normalizeBar('energy', { current: 'nope' }), null);
  assert.equal(normalizeBar('energy', undefined), null);
});
