'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  TargetFinder,
  battleStatScore,
  estimateFromFairFight,
  candidatesFromAttacks,
  filterTargets,
  readFairFight,
} = require('../src/targets');

const ME = 777;
const CFG = { minLevel: 20, maxStats: 400, maxLookups: 25 };

test('battleStatScore additionne les racines carrees des quatre stats', () => {
  assert.equal(battleStatScore({ strength: 2500, defense: 2500, speed: 2500, dexterity: 2500 }), 200);
  assert.equal(battleStatScore({ strength: '100', defense: '100', speed: '100', dexterity: '100' }), 40);
  assert.equal(battleStatScore({ strength: 0, defense: 0, speed: 0, dexterity: 0 }), 0);
});

test('battleStatScore refuse des stats incompletes ou aberrantes', () => {
  assert.equal(battleStatScore({ strength: 100, defense: 100, speed: 100 }), null);
  assert.equal(battleStatScore({ strength: -1, defense: 1, speed: 1, dexterity: 1 }), null);
  assert.equal(battleStatScore(null), null);
});

test('estimateFromFairFight applique la formule du score defenseur', () => {
  // DefenderScore = (FF-1) * 3/8 * AttackerScore ; Stats = Score^2 / 4
  const e = estimateFromFairFight(1.4, 200);
  assert.equal(e.score, 30);
  assert.equal(e.stats, 225);
  assert.equal(e.resolved, true);
});

test('un Fair Fight au plancher signale une cible sous le seuil de mesure', () => {
  const e = estimateFromFairFight(1, 200);
  assert.equal(e.resolved, false);
  assert.equal(e.stats, 0);
  assert.equal(estimateFromFairFight(0.5, 200).resolved, false);
});

test('estimateFromFairFight rejette des entrees inexploitables', () => {
  assert.equal(estimateFromFairFight(null, 200), null);
  assert.equal(estimateFromFairFight(1.5, 0), null);
  assert.equal(estimateFromFairFight('beaucoup', 200), null);
});

test('readFairFight lit les differentes formes de modificateur', () => {
  assert.equal(readFairFight({ modifiers: { fairFight: 1.8 } }), 1.8);
  assert.equal(readFairFight({ modifiers: { fair_fight: '2.2' } }), 2.2);
  assert.equal(readFairFight({ fair_fight: 1.1 }), 1.1);
  assert.equal(readFairFight({ modifiers: {} }), null);
});

function attack(defender, ff, { level = null, ts = 1000, result = 'Attacked' } = {}) {
  return {
    attacker_id: ME,
    defender_id: defender,
    defender_name: 'Cible' + defender,
    defender_level: level,
    result,
    respect_gain: 3,
    timestamp_ended: ts,
    modifiers: { fairFight: ff },
  };
}

test('candidatesFromAttacks regroupe par defenseur et retient le FF maximal', () => {
  const c = candidatesFromAttacks(
    { attacks: { a: attack(11, 1.2, { ts: 1000 }), b: attack(11, 1.6, { ts: 2000 }), c: attack(12, 1.3) } },
    ME
  );
  assert.equal(c.length, 2);
  const first = c.find((x) => x.id === 11);
  assert.equal(first.fairFight, 1.6, 'le FF le plus informatif est conserve');
  assert.equal(first.attacks, 2);
  assert.equal(first.lastAttack, 2000000);
});

test('candidatesFromAttacks ignore les attaques subies', () => {
  const c = candidatesFromAttacks(
    { attacks: { a: attack(11, 1.5), b: { ...attack(ME, 1.9), attacker_id: 999 } } },
    ME
  );
  assert.deepEqual(c.map((x) => x.id), [11]);
});

test('filterTargets ecarte les niveaux trop bas et les stats trop hautes', () => {
  const { kept, rejected } = filterTargets(
    [
      { id: 1, level: 45, stats: 200 },
      { id: 2, level: 12, stats: 100 },
      { id: 3, level: 60, stats: 9000 },
    ],
    CFG
  );
  assert.deepEqual(kept.map((t) => t.id), [1]);
  assert.equal(rejected.length, 2);
  assert.match(rejected.find((r) => r.id === 2).reason, /niveau 12/);
  assert.match(rejected.find((r) => r.id === 3).reason, /stats estimees/);
});

test('filterTargets conserve les cibles dont les stats sont inconnues', () => {
  const { kept } = filterTargets([{ id: 1, level: 40, stats: null }], CFG);
  assert.deepEqual(kept.map((t) => t.id), [1]);
});

test('filterTargets classe les cibles par niveau decroissant', () => {
  const { kept } = filterTargets(
    [
      { id: 1, level: 25, stats: 100 },
      { id: 2, level: 70, stats: 100 },
      { id: 3, level: 40, stats: 100 },
    ],
    CFG
  );
  assert.deepEqual(kept.map((t) => t.level), [70, 40, 25]);
});

/** Faux client API : stats perso, journal d'attaques, profils. */
function fakeApi({ stats, attacks = {}, profiles = {} }) {
  const calls = [];
  const nowSec = Math.floor(Date.now() / 1000);
  return {
    calls,
    states: {},
    async get(section, selections = []) {
      calls.push(`${section}:${selections.join(',')}`);
      if (section === 'user' && selections.includes('battlestats')) return stats;
      if (section === 'user' && selections.includes('basic')) return { player_id: ME };
      if (section === 'user' && selections.includes('attacks')) return { attacks };
      const id = Number(section.split('/')[1]);
      if (!(id in profiles)) throw new Error('profil inaccessible');
      const p = profiles[id];
      return {
        name: p.name,
        level: p.level,
        rank: p.rank,
        last_action: { timestamp: nowSec - (p.idleDays ?? 0) * 86400 },
        faction: p.faction ? { faction_name: p.faction } : {},
        status: { state: this?.states?.[id] ?? p.state ?? 'Okay' },
      };
    },
  };
}

const MY_STATS = { strength: 2500, defense: 2500, speed: 2500, dexterity: 2500 }; // BSS = 200

test('find estime les stats des cibles et applique les filtres', async () => {
  const api = fakeApi({
    stats: MY_STATS,
    attacks: { a: attack(11, 1.4), b: attack(12, 2.5) },
    profiles: {
      11: { name: 'Faible', level: 42, rank: 'Beginner', idleDays: 30 },
      12: { name: 'Costaud', level: 50, rank: 'Elite', faction: 'Big Faction' },
    },
  });

  const result = await new TargetFinder(api, CFG).find();
  assert.equal(result.attackScore, 200);
  assert.deepEqual(result.targets.map((t) => t.id), [11], 'seul le joueur sous 400 stats est retenu');
  assert.equal(result.targets[0].stats, 225);
  assert.equal(result.targets[0].rank, 'Beginner');
  assert.equal(result.targets[0].lastActionDays, 30);
  assert.equal(result.targets[0].faction, null);
  assert.match(result.rejected[0].reason, /stats estimees/);
});

test('une cible au plancher de Fair Fight est marquee comme non resolue', async () => {
  const api = fakeApi({
    stats: MY_STATS,
    attacks: { a: attack(11, 1) },
    profiles: { 11: { name: 'Minuscule', level: 35, rank: 'Beginner' } },
  });
  const result = await new TargetFinder(api, CFG).find();
  assert.equal(result.targets[0].stats, null);
  assert.equal(result.targets[0].belowResolution, true);
});

test('--ids ajoute des candidats sans historique d’attaque', async () => {
  const api = fakeApi({
    stats: MY_STATS,
    attacks: {},
    profiles: { 99: { name: 'Externe', level: 40, rank: 'Beginner' } },
  });
  const result = await new TargetFinder(api, CFG).find({ extraIds: [99] });
  assert.equal(result.targets.length, 1);
  assert.equal(result.targets[0].id, 99);
  assert.equal(result.targets[0].stats, null, 'sans Fair Fight, aucune estimation n’est inventee');
  assert.equal(result.targets[0].belowResolution, false);
});

test('--ids ne duplique pas un joueur deja present dans l’historique', async () => {
  const api = fakeApi({
    stats: MY_STATS,
    attacks: { a: attack(11, 1.4) },
    profiles: { 11: { name: 'Faible', level: 42 } },
  });
  const result = await new TargetFinder(api, CFG).find({ extraIds: [11] });
  assert.equal(result.inspected, 1);
});

test('un profil inaccessible n’elimine pas la cible', async () => {
  const api = fakeApi({ stats: MY_STATS, attacks: { a: attack(11, 1.4) }, profiles: {} });
  const result = await new TargetFinder(api, CFG).find();
  assert.equal(result.inspected, 1);
  assert.equal(result.targets[0].id, 11);
  assert.equal(result.targets[0].level, null);
});

test('le nombre de profils consultes est plafonne', async () => {
  const attacks = {};
  for (let i = 0; i < 10; i += 1) attacks[`a${i}`] = attack(100 + i, 1.4);
  const api = fakeApi({ stats: MY_STATS, attacks, profiles: {} });
  const result = await new TargetFinder(api, { ...CFG, maxLookups: 3 }).find();
  assert.equal(result.inspected, 3);
  assert.equal(result.truncated, true);
});

test('des battle stats illisibles produisent une erreur explicite', async () => {
  const api = fakeApi({ stats: {}, attacks: {} });
  await assert.rejects(() => new TargetFinder(api, CFG).find(), /battlestats/);
});

test('un compte en prison federale est toujours ecarte : il est inattaquable', () => {
  const cfg = { ...CFG, excludeStates: ['Federal'] };
  const { kept, rejected } = filterTargets(
    [
      { id: 1, level: 55, stats: 200, state: 'Federal', rank: 'Beginner' },
      { id: 2, level: 45, stats: 200, state: 'Okay', rank: 'Beginner' },
    ],
    cfg
  );
  assert.deepEqual(kept.map((t) => t.id), [2]);
  assert.match(rejected[0].reason, /Federal/);
});

test('le filtre de rang retient les rangs demandes, quelle que soit la casse', () => {
  const cfg = { ...CFG, ranks: ['beginner'] };
  const { kept } = filterTargets(
    [
      { id: 1, level: 55, stats: null, rank: 'Absolute beginner', state: 'Okay' },
      { id: 2, level: 50, stats: null, rank: 'Beginner', state: 'Okay' },
      { id: 3, level: 60, stats: null, rank: 'Elite', state: 'Okay' },
      { id: 4, level: 48, stats: null, rank: null, state: 'Okay' },
    ],
    cfg
  );
  assert.deepEqual(kept.map((t) => t.id), [1, 2], 'rang inconnu exclu quand un filtre est demande');
});

test('sans filtre de rang, aucune cible n’est ecartee sur ce critere', () => {
  const { kept } = filterTargets([{ id: 1, level: 50, stats: null, rank: 'Elite', state: 'Okay' }], CFG);
  assert.equal(kept.length, 1);
});

test('maxIdleDays ecarte les comptes trop anciennement actifs', () => {
  const cfg = { ...CFG, maxIdleDays: 90 };
  const { kept, rejected } = filterTargets(
    [
      { id: 1, level: 50, stats: null, lastActionDays: 400, state: 'Okay' },
      { id: 2, level: 45, stats: null, lastActionDays: 10, state: 'Okay' },
      { id: 3, level: 44, stats: null, lastActionDays: null, state: 'Okay' },
    ],
    cfg
  );
  assert.deepEqual(kept.map((t) => t.id), [2, 3], 'une inactivite inconnue ne disqualifie pas');
  assert.match(rejected[0].reason, /inactif depuis 400j/);
});

test('la requete complete : niveau > 40, rang Beginner, hors prison federale', async () => {
  const api = fakeApi({
    stats: MY_STATS,
    attacks: { a: attack(11, 1.3), b: attack(12, 1.3), c: attack(13, 1.3), d: attack(14, 1.3) },
    profiles: {
      11: { name: 'Dormant', level: 62, rank: 'Beginner' },
      12: { name: 'Fedde', level: 71, rank: 'Beginner' },
      13: { name: 'Costaud', level: 55, rank: 'Elite' },
      14: { name: 'TropBas', level: 25, rank: 'Beginner' },
    },
  });
  api.states = { 12: 'Federal' };

  const result = await new TargetFinder(api, {
    ...CFG,
    minLevel: 41,
    ranks: ['beginner'],
    excludeStates: ['Federal'],
  }).find();

  assert.deepEqual(result.targets.map((t) => t.name), ['Dormant']);
  assert.ok(result.rejected.some((r) => /Federal/.test(r.reason)), 'le compte fedde est ecarte');
});
