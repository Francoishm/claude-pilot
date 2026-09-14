'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { MarketSweeper, selectScannableItems } = require('../src/sweep');
const { createApp } = require('../src/dashboard');

const CFG = {
  minDiscountPercent: 20,
  minNetMarginPercent: 10,
  minMarketValue: 50000,
  minProfitPerUnit: 10000,
  maxCashPerBuy: 0,
  salesFeePercent: 5,
  sellUndercutPercent: 0,
  staleSeconds: 1800,
  maxItems: 0,
};

test('selectScannableItems ecarte les objets sous le plancher de valeur', () => {
  const items = [
    { id: 1, name: 'Cher', marketValue: 1000000 },
    { id: 2, name: 'Moyen', marketValue: 60000 },
    { id: 3, name: 'Babiole', marketValue: 500 },
  ];
  assert.deepEqual(selectScannableItems(items, CFG).map((i) => i.id), [1, 2]);
});

test('selectScannableItems classe par valeur decroissante et respecte maxItems', () => {
  const items = [
    { id: 1, marketValue: 60000 },
    { id: 2, marketValue: 900000 },
    { id: 3, marketValue: 300000 },
  ];
  assert.deepEqual(selectScannableItems(items, CFG).map((i) => i.id), [2, 3, 1]);
  assert.deepEqual(selectScannableItems(items, { ...CFG, maxItems: 2 }).map((i) => i.id), [2, 3]);
});

const CATALOGUE = {
  1: { name: 'Objet Cher', type: 'Drug', market_value: 1000000 },
  2: { name: 'Objet Moyen', type: 'Drug', market_value: 200000 },
  3: { name: 'Babiole', type: 'Other', market_value: 300 },
};

/** Faux client API : catalogue fixe, annonces modifiables entre les passages. */
function fakeApi(listings = {}) {
  const calls = [];
  const api = {
    calls,
    listings,
    async get(section, selections = []) {
      calls.push(section);
      if (section === 'torn') return { items: CATALOGUE };
      const id = Number(section.split('/')[1]);
      if (api.failOn === id) throw new Error('Torn a refuse la requete');
      return api.listings[id] ?? { itemmarket: [], bazaar: [] };
    },
  };
  return api;
}

test('loadQueue ne retient que les objets balayables', async () => {
  const sweeper = new MarketSweeper(fakeApi(), CFG);
  assert.equal(await sweeper.loadQueue(), 2);
  assert.deepEqual(sweeper.queue.map((i) => i.name), ['Objet Cher', 'Objet Moyen']);
});

test('une annonce sous-cotee devient une affaire avec marge nette apres taxe', async () => {
  const api = fakeApi({ 1: { itemmarket: [{ cost: 700000, quantity: 2 }] } });
  const sweeper = new MarketSweeper(api, CFG);
  await sweeper.loadQueue();
  await sweeper.tick(1);

  const [o] = sweeper.state.opportunities;
  assert.equal(o.name, 'Objet Cher');
  assert.equal(o.discountPercent, 30, 'remise brute');
  // Revente a 1 000 000 moins 5 % de taxe = 950 000, moins 700 000 d'achat.
  assert.equal(o.profitPerUnit, 250000);
  assert.equal(o.totalProfit, 500000);
  assert.ok(o.foundAt > 0);
});

test('la taxe de vente peut annuler une affaire brute', async () => {
  // -20 % brut, mais une taxe de 25 % rendrait l'operation perdante.
  const api = fakeApi({ 1: { itemmarket: [{ cost: 800000, quantity: 1 }] } });
  const sweeper = new MarketSweeper(api, { ...CFG, salesFeePercent: 25, minProfitPerUnit: 0 });
  await sweeper.loadQueue();
  await sweeper.tick(1);
  assert.equal(sweeper.state.opportunities.length, 0);
});

test('une affaire disparue est retiree du tableau au passage suivant', async () => {
  const api = fakeApi({ 1: { itemmarket: [{ cost: 700000, quantity: 2 }] } });
  const sweeper = new MarketSweeper(api, CFG);
  await sweeper.loadQueue();
  await sweeper.tick(1);
  assert.equal(sweeper.state.opportunities.length, 1);

  api.listings[1] = { itemmarket: [{ cost: 990000, quantity: 2 }] };
  sweeper.cursor = 0;
  await sweeper.tick(1);
  assert.equal(sweeper.state.opportunities.length, 0, 'l’annonce partie ne reste pas affichee');
});

test('pruneStale retire les affaires qu’aucun passage recent n’a confirmees', async () => {
  const api = fakeApi({ 1: { itemmarket: [{ cost: 700000, quantity: 1 }] } });
  const sweeper = new MarketSweeper(api, { ...CFG, staleSeconds: 60 });
  await sweeper.loadQueue();
  await sweeper.tick(1);
  assert.equal(sweeper.state.opportunities.length, 1);

  sweeper.pruneStale(Date.now() + 120000);
  assert.equal(sweeper.state.opportunities.length, 0);
});

test('un objet en echec n’arrete pas le balayage et est signale', async () => {
  const api = fakeApi({ 2: { itemmarket: [{ cost: 120000, quantity: 1 }] } });
  api.failOn = 1;
  const sweeper = new MarketSweeper(api, CFG);
  await sweeper.loadQueue();
  await sweeper.tick(2);

  assert.equal(sweeper.state.opportunities.length, 1, 'le second objet a bien ete traite');
  assert.equal(sweeper.state.opportunities[0].name, 'Objet Moyen');
  assert.equal(sweeper.lastError, null, 'l’erreur est effacee par le succes suivant');
});

test('le curseur boucle et incremente le compteur de cycles', async () => {
  const sweeper = new MarketSweeper(fakeApi(), CFG);
  await sweeper.loadQueue();
  await sweeper.tick(2);
  assert.equal(sweeper.cycles, 1);
  assert.equal(sweeper.cursor, 0);
  assert.equal(sweeper.scannedThisCycle, 0, 'le compteur repart a chaque cycle');
});

test('les affaires sont triees par marge totale decroissante', async () => {
  const api = fakeApi({
    1: { itemmarket: [{ cost: 700000, quantity: 1 }] },   // 250 000 net
    2: { itemmarket: [{ cost: 120000, quantity: 10 }] },  // 70 000 x 10
  });
  const sweeper = new MarketSweeper(api, CFG);
  await sweeper.loadQueue();
  await sweeper.tick(2);
  assert.deepEqual(sweeper.state.opportunities.map((o) => o.name), ['Objet Moyen', 'Objet Cher']);
});

test('le dashboard sert l’etat du balayage, et 503 sans balayage', async () => {
  const api = fakeApi({ 1: { itemmarket: [{ cost: 700000, quantity: 1 }] } });
  const sweeper = new MarketSweeper(api, CFG);
  await sweeper.loadQueue();
  await sweeper.tick(1);

  const coach = { poll: async () => ({ snapshot: {}, result: {} }), tracker: { report: () => ({}) } };
  const withSweep = createApp(coach, sweeper).listen(0, '127.0.0.1');
  const without = createApp(coach).listen(0, '127.0.0.1');
  await Promise.all([
    new Promise((r) => withSweep.once('listening', r)),
    new Promise((r) => without.once('listening', r)),
  ]);

  try {
    const state = await fetch(`http://127.0.0.1:${withSweep.address().port}/api/market`).then((r) => r.json());
    assert.equal(state.opportunities.length, 1);
    assert.equal(state.config.salesFeePercent, 5);

    const res = await fetch(`http://127.0.0.1:${without.address().port}/api/market`);
    assert.equal(res.status, 503);
  } finally {
    withSweep.close();
    without.close();
  }
});
