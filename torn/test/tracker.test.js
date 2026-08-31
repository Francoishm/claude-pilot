'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Tracker, summarize, wastedBetween } = require('../src/tracker');
const { buildSnapshot } = require('../src/snapshot');

function rec(ts, energyCurrent, level = 10) {
  return {
    ts,
    level,
    state: 'Okay',
    energy: { c: energyCurrent, m: 150, i: 5, t: 600 },
    nerve: { c: 5, m: 22, i: 1, t: 300 },
  };
}

test('aucun gaspillage quand la barre n’est pas pleine', () => {
  assert.equal(wastedBetween(rec(0, 100), rec(600000, 105), 'energy'), 0);
});

test('barre pleine sur tout l’intervalle : la regen est perdue', () => {
  // 600s pleine, +5 energie toutes les 600s => 5 perdues.
  assert.equal(wastedBetween(rec(0, 150), rec(600000, 150), 'energy'), 5);
});

test('summarize agrege gaspillage et montees de niveau', () => {
  const report = summarize([rec(0, 150, 10), rec(600000, 150, 10), rec(1200000, 150, 11)]);
  assert.equal(report.samples, 3);
  assert.equal(report.wasted.energy, 10);
  assert.equal(report.fullSeconds.energy, 1200);
  assert.deepEqual(report.levelUps, [{ at: 1200000, from: 10, to: 11 }]);
});

test('un trou de plus d’une heure ne compte pas comme du gaspillage', () => {
  const report = summarize([rec(0, 150), rec(4 * 3600 * 1000, 150)]);
  assert.equal(report.wasted.energy, 0);
});

test('summarize gere un historique vide', () => {
  const report = summarize([]);
  assert.equal(report.samples, 0);
  assert.equal(report.wasted.energy, 0);
  assert.deepEqual(report.levelUps, []);
});

test('Tracker ecrit puis relit son historique et ignore les lignes corrompues', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torn-'));
  const file = path.join(dir, 'nested', 'history.jsonl');
  const tracker = new Tracker({ file });

  assert.deepEqual(tracker.load(), [], 'un fichier absent donne un historique vide');

  const snapshot = buildSnapshot(
    { level: 12, status: { state: 'Okay' }, energy: { current: 150, maximum: 150, increment: 5, interval: 600, fulltime: 0 } },
    5000
  );
  tracker.record(snapshot);
  fs.appendFileSync(file, '{ ceci n’est pas du json\n');
  tracker.record(snapshot);

  const rows = tracker.load();
  assert.equal(rows.length, 2);
  assert.equal(rows[0].level, 12);
  assert.equal(rows[0].energy.c, 150);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('report filtre sur la fenetre demandee', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torn-'));
  const file = path.join(dir, 'history.jsonl');
  fs.writeFileSync(file, [rec(1000, 150), rec(2000, 150), rec(900000, 150)].map((r) => JSON.stringify(r)).join('\n'));
  assert.equal(new Tracker({ file }).report(0).samples, 3);
  assert.equal(new Tracker({ file }).report(500000).samples, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});
