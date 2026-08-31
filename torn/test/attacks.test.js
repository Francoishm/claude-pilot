'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { AttackAnalyzer, normalizeAttacks, summarizeAttacks, attackAdvice, classifyResult } = require('../src/attacks');

const CFG = { attacksToLevel15: 125, minTargetLevel: 30, maxEnrichLookups: 25 };
const ME = 777;

function attack(id, result, { defender = 100, level = null, respect = 3, ts = 1000 } = {}) {
  return {
    code: String(id),
    timestamp_started: ts - 60,
    timestamp_ended: ts,
    attacker_id: ME,
    defender_id: defender,
    defender_name: 'Cible' + defender,
    defender_level: level,
    result,
    respect_gain: respect,
    modifiers: { fairFight: 1.5, chainBonus: 1 },
  };
}

test('classifyResult range les issues par rendement XP', () => {
  assert.equal(classifyResult('Attacked'), 'leave');
  assert.equal(classifyResult('mugged'), 'mug');
  assert.equal(classifyResult('Hospitalized'), 'hosp');
  assert.equal(classifyResult('Lost'), 'loss');
  assert.equal(classifyResult('Chose un truc inconnu'), 'other');
  assert.equal(classifyResult(undefined), 'other');
});

test('normalizeAttacks accepte l’objet indexe (v1) et le tableau (v2)', () => {
  const asObject = normalizeAttacks({ attacks: { a: attack(1, 'Attacked'), b: attack(2, 'Mugged') } }, ME);
  const asArray = normalizeAttacks([attack(1, 'Attacked'), attack(2, 'Mugged')], ME);
  assert.equal(asObject.length, 2);
  assert.equal(asArray.length, 2);
  assert.deepEqual(asObject.map((a) => a.class), ['leave', 'mug']);
});

test('normalizeAttacks ecarte les attaques subies', () => {
  const rows = normalizeAttacks(
    { attacks: { a: attack(1, 'Attacked'), b: { ...attack(2, 'Lost'), attacker_id: 999, defender_id: ME } } },
    ME
  );
  assert.equal(rows.length, 1);
  assert.equal(rows[0].class, 'leave');
});

test('normalizeAttacks trie par date et tolere un journal vide', () => {
  const rows = normalizeAttacks({ attacks: { a: attack(1, 'Attacked', { ts: 5000 }), b: attack(2, 'Attacked', { ts: 1000 }) } }, ME);
  assert.deepEqual(rows.map((a) => a.at), [1000000, 5000000]);
  assert.deepEqual(normalizeAttacks(null, ME), []);
  assert.deepEqual(normalizeAttacks({ attacks: {} }, ME), []);
});

test('normalizeAttacks lit le respect sous ses deux noms de champ', () => {
  const [v1] = normalizeAttacks([attack(1, 'Attacked', { respect: 4 })], ME);
  const [v2] = normalizeAttacks([{ ...attack(2, 'Attacked'), respect_gain: undefined, respect: 7 }], ME);
  assert.equal(v1.respect, 4);
  assert.equal(v2.respect, 7);
});

test('summarizeAttacks compte les issues et calcule l’efficacite XP', () => {
  const rows = normalizeAttacks(
    [
      attack(1, 'Attacked', { level: 40 }),
      attack(2, 'Attacked', { level: 50 }),
      attack(3, 'Mugged', { level: 45 }),
      attack(4, 'Hospitalized', { level: 45 }),
      attack(5, 'Lost'),
    ],
    ME
  );
  const s = summarizeAttacks(rows, CFG);
  assert.equal(s.total, 5);
  assert.equal(s.won, 4);
  assert.equal(s.counts.leave, 2);
  assert.equal(s.suboptimal, 2);
  assert.equal(s.leaveRatio, 0.5);
  assert.equal(s.averageDefenderLevel, 45);
  assert.equal(s.defenderLevelsKnown, 4);
});

test('summarizeAttacks gere un journal vide sans planter', () => {
  const s = summarizeAttacks([], CFG);
  assert.equal(s.total, 0);
  assert.equal(s.leaveRatio, null);
  assert.equal(s.averageDefenderLevel, null);
});

test('l’analyse signale les victoires mal conclues', () => {
  const rows = normalizeAttacks([attack(1, 'Attacked', { level: 40 }), attack(2, 'Mugged', { level: 40 })], ME);
  const ids = attackAdvice(summarizeAttacks(rows, CFG), CFG).map((a) => a.id);
  assert.ok(ids.includes('not-leaving'));
});

test('l’analyse signale des cibles de niveau trop bas', () => {
  const rows = normalizeAttacks([attack(1, 'Attacked', { level: 5 }), attack(2, 'Attacked', { level: 7 })], ME);
  const ids = attackAdvice(summarizeAttacks(rows, CFG), CFG).map((a) => a.id);
  assert.ok(ids.includes('targets-too-low'));
  assert.ok(!ids.includes('not-leaving'), 'des attaques bien conclues ne sont pas reprochees');
});

test('l’analyse propose --enrich quand aucun niveau n’est connu', () => {
  const rows = normalizeAttacks([attack(1, 'Attacked')], ME);
  const ids = attackAdvice(summarizeAttacks(rows, CFG), CFG).map((a) => a.id);
  assert.ok(ids.includes('levels-unknown'));
});

test('le repere communautaire compte les attaques restantes', () => {
  const rows = normalizeAttacks([attack(1, 'Attacked', { level: 40 })], ME);
  const benchmark = attackAdvice(summarizeAttacks(rows, CFG), CFG).find((a) => a.id === 'benchmark');
  assert.match(benchmark.detail, /124 restantes/);
  assert.match(benchmark.title, /~125/);
});

test('un journal sans victoire le dit au lieu de conseiller a vide', () => {
  const rows = normalizeAttacks([attack(1, 'Lost')], ME);
  const advice = attackAdvice(summarizeAttacks(rows, CFG), CFG);
  assert.deepEqual(advice.map((a) => a.id), ['no-wins']);
});

/** Faux client API : journal + profils, avec comptage des appels. */
function fakeApi({ attacks, profiles = {} }) {
  const calls = [];
  return {
    calls,
    async get(section, selections) {
      calls.push(`${section}:${(selections || []).join(',')}`);
      if (section === 'user' && selections.includes('basic')) return { player_id: ME };
      if (section === 'user') return { attacks };
      const id = Number(section.split('/')[1]);
      if (!(id in profiles)) throw new Error('profil inaccessible');
      return { level: profiles[id] };
    },
  };
}

test('analyze recupere le journal et le filtre sur mon identifiant', async () => {
  const api = fakeApi({
    attacks: { a: attack(1, 'Attacked'), b: { ...attack(2, 'Lost'), attacker_id: 999 } },
  });
  const { summary } = await new AttackAnalyzer(api, CFG).analyze();
  assert.equal(summary.total, 1);
});

test('--enrich complete le niveau des cibles et met en cache par joueur', async () => {
  const api = fakeApi({
    attacks: { a: attack(1, 'Attacked', { defender: 11 }), b: attack(2, 'Attacked', { defender: 11 }), c: attack(3, 'Attacked', { defender: 12 }) },
    profiles: { 11: 55, 12: 60 },
  });
  const { summary } = await new AttackAnalyzer(api, CFG).analyze({ enrich: true });

  assert.equal(summary.averageDefenderLevel, Math.round(((55 + 55 + 60) / 3) * 10) / 10);
  assert.equal(api.calls.filter((c) => c.startsWith('user/')).length, 2, 'un appel par joueur distinct');
});

test('--enrich respecte le plafond d’appels', async () => {
  const attacks = {};
  const profiles = {};
  for (let i = 0; i < 10; i += 1) {
    attacks[`a${i}`] = attack(i, 'Attacked', { defender: 100 + i });
    profiles[100 + i] = 40;
  }
  const api = fakeApi({ attacks, profiles });
  await new AttackAnalyzer(api, { ...CFG, maxEnrichLookups: 3 }).analyze({ enrich: true });
  assert.equal(api.calls.filter((c) => c.startsWith('user/')).length, 3);
});

test('un profil inaccessible n’interrompt pas l’enrichissement', async () => {
  const api = fakeApi({
    attacks: { a: attack(1, 'Attacked', { defender: 11 }), b: attack(2, 'Attacked', { defender: 12 }) },
    profiles: { 11: 50 },
  });
  const { summary } = await new AttackAnalyzer(api, CFG).analyze({ enrich: true });
  assert.equal(summary.averageDefenderLevel, 50);
  assert.equal(summary.defenderLevelsKnown, 1);
});
