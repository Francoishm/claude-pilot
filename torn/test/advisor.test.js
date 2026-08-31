'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { buildSnapshot } = require('../src/snapshot');
const { advise, formatSeconds } = require('../src/advisor');

function snap(overrides = {}) {
  return buildSnapshot(
    {
      name: 'Tester',
      level: 15,
      status: { state: 'Okay', until: 0 },
      energy: { current: 20, maximum: 150, increment: 5, interval: 600, ticktime: 100, fulltime: 15000 },
      nerve: { current: 2, maximum: 22, increment: 1, interval: 300, ticktime: 100, fulltime: 6000 },
      happy: { current: 3000, maximum: 4000, increment: 5, interval: 900, ticktime: 100, fulltime: 90000 },
      life: { current: 1000, maximum: 1000, increment: 100, interval: 300, ticktime: 0, fulltime: 0 },
      cooldowns: { drug: 500, medical: 0, booster: 0 },
      refills: { energy_refill_used: true, nerve_refill_used: true },
      education: { education_current: 12, education_timeleft: 5000 },
      travel: { time_left: 0 },
      ...overrides,
    },
    1000
  );
}

const ids = (r) => r.advice.map((a) => a.id);

test('une barre pleine remonte en tete des conseils', () => {
  const r = advise(snap({ nerve: { current: 22, maximum: 22, increment: 1, interval: 300, ticktime: 0, fulltime: 0 } }));
  assert.equal(r.next.id, 'nerve-full');
  assert.equal(r.next.priority, 100);
});

test('la chaine active passe devant une barre pleine', () => {
  const r = advise(
    snap({
      nerve: { current: 22, maximum: 22, increment: 1, interval: 300, ticktime: 0, fulltime: 0 },
      chain: { current: 25, maximum: 100, timeout: 200 },
    })
  );
  assert.equal(r.next.id, 'chain-active');
});

test('un debordement imminent est signale avant la saturation', () => {
  const r = advise(snap({ energy: { current: 145, maximum: 150, increment: 5, interval: 600, ticktime: 100, fulltime: 500 } }));
  assert.ok(ids(r).includes('energy-soon'));
  assert.ok(!ids(r).includes('energy-full'));
});

test('le vol en cours bloque toute recommandation de depense', () => {
  const r = advise(
    snap({
      travel: { destination: 'Mexico', time_left: 900 },
      energy: { current: 150, maximum: 150, increment: 5, interval: 600, ticktime: 0, fulltime: 0 },
    })
  );
  assert.equal(r.next, null);
  assert.equal(r.blockers[0].id, 'traveling');
  // Les conseils restent visibles, ils ne sont juste pas actionnables.
  assert.ok(ids(r).includes('energy-full'));
});

test('l’hopital bloque aussi la depense', () => {
  const r = advise(snap({ status: { state: 'Hospital', description: 'Mauvaise chute', until: 600 } }));
  assert.equal(r.next, null);
  assert.equal(r.blockers[0].id, 'hospital');
});

test('les refills quotidiens inutilises sont signales', () => {
  const r = advise(snap({ refills: { energy_refill_used: false, nerve_refill_used: false } }));
  assert.ok(ids(r).includes('refill-energy'));
  assert.ok(ids(r).includes('refill-nerve'));
});

test('un happy au plancher declenche un avertissement avant le gym', () => {
  const r = advise(snap({ happy: { current: 100, maximum: 4000, increment: 5, interval: 900, ticktime: 100, fulltime: 9000 } }));
  assert.ok(ids(r).includes('happy-low'));
});

test('happy bas sans energie a depenser ne declenche rien', () => {
  const r = advise(
    snap({
      happy: { current: 100, maximum: 4000, increment: 5, interval: 900, ticktime: 100, fulltime: 9000 },
      energy: { current: 0, maximum: 150, increment: 5, interval: 600, ticktime: 100, fulltime: 18000 },
    })
  );
  assert.ok(!ids(r).includes('happy-low'));
});

test('cooldown drogue termine et energie basse suggerent une relance', () => {
  const r = advise(snap({ cooldowns: { drug: 0, medical: 0, booster: 0 } }));
  assert.ok(ids(r).includes('drug-cooldown-clear'));
});

test('cooldown drogue termine mais energie haute ne suggere rien', () => {
  const r = advise(
    snap({
      cooldowns: { drug: 0, medical: 0, booster: 0 },
      energy: { current: 140, maximum: 150, increment: 5, interval: 600, ticktime: 100, fulltime: 1200 },
    })
  );
  assert.ok(!ids(r).includes('drug-cooldown-clear'));
});

test('un cours termine est signale en entretien', () => {
  const r = advise(snap({ education: { education_current: 12, education_timeleft: 0 } }));
  assert.ok(ids(r).includes('education-idle'));
});

test('des barres calmes ne produisent aucune action urgente', () => {
  const r = advise(snap());
  assert.equal(r.blockers.length, 0);
  assert.equal(r.advice.length, 0);
  assert.equal(r.next, null);
});

test('la config peut etre surchargee', () => {
  const s = snap({ energy: { current: 100, maximum: 150, increment: 5, interval: 600, ticktime: 100, fulltime: 6000 } });
  assert.ok(!ids(advise(s)).includes('energy-high'));
  assert.ok(ids(advise(s, { wasteWarningRatio: 0.5 })).includes('energy-high'));
});

test('formatSeconds reste lisible a toutes les echelles', () => {
  assert.equal(formatSeconds(45), '45s');
  assert.equal(formatSeconds(90), '1m 30s');
  assert.equal(formatSeconds(600), '10m');
  assert.equal(formatSeconds(3600), '1h');
  assert.equal(formatSeconds(5400), '1h 30m');
  assert.equal(formatSeconds(null), '?');
});
