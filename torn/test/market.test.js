'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { MarketScanner, findOpportunity, normalizeListings, indexCatalogue } = require('../src/market');

const CFG = { minDiscountPercent: 12, minProfitPerUnit: 25000, maxCashPerBuy: 0 };
const XANAX = { id: 206, name: 'Xanax', marketValue: 800000 };

test('normalizeListings accepte les variantes de champs et rejette le bruit', () => {
  const rows = normalizeListings(
    [
      { cost: 700000, quantity: 3 },
      { price: '650000', amount: '2' },
      { cost: 0, quantity: 5 },
      { cost: 100, quantity: 0 },
      { nothing: true },
    ],
    'itemmarket'
  );
  assert.deepEqual(rows, [
    { cost: 700000, quantity: 3, source: 'itemmarket' },
    { cost: 650000, quantity: 2, source: 'itemmarket' },
  ]);
});

test('normalizeListings tolere une reponse vide ou malformee', () => {
  assert.deepEqual(normalizeListings(null, 'bazaar'), []);
  assert.deepEqual(normalizeListings({}, 'bazaar'), []);
});

test('une annonce nettement sous la valeur marche est retenue', () => {
  const o = findOpportunity(XANAX, [{ cost: 900000, quantity: 1, source: 'itemmarket' }, { cost: 600000, quantity: 4, source: 'itemmarket' }], CFG);
  assert.equal(o.cost, 600000, 'la meilleure annonce est la moins chere');
  assert.equal(o.profitPerUnit, 200000);
  assert.equal(o.totalProfit, 800000);
  assert.equal(o.discountPercent, 25);
});

test('une remise sous le seuil est ignoree', () => {
  assert.equal(findOpportunity(XANAX, [{ cost: 760000, quantity: 1, source: 'itemmarket' }], CFG), null);
});

test('une marge unitaire insuffisante est ignoree malgre un bon pourcentage', () => {
  const cheap = { id: 1, name: 'Babouche', marketValue: 100000 };
  // -20 % mais seulement 20 000 de marge : sous minProfitPerUnit.
  assert.equal(findOpportunity(cheap, [{ cost: 80000, quantity: 1, source: 'bazaar' }], CFG), null);
});

test('une annonce au-dessus de la valeur marche n’est jamais une opportunite', () => {
  assert.equal(findOpportunity(XANAX, [{ cost: 950000, quantity: 1, source: 'bazaar' }], CFG), null);
});

test('le budget limite le nombre d’unites et la marge annoncee', () => {
  const o = findOpportunity(XANAX, [{ cost: 600000, quantity: 10, source: 'itemmarket' }], { ...CFG, maxCashPerBuy: 1500000 });
  assert.equal(o.affordable, 2);
  assert.equal(o.totalProfit, 400000);
  assert.equal(o.quantity, 10, 'la quantite disponible reste visible');
});

test('un budget trop faible pour une seule unite ecarte l’opportunite', () => {
  assert.equal(findOpportunity(XANAX, [{ cost: 600000, quantity: 10, source: 'itemmarket' }], { ...CFG, maxCashPerBuy: 100000 }), null);
});

test('un objet sans valeur de marche ou sans annonce ne produit rien', () => {
  assert.equal(findOpportunity({ id: 1, name: 'X', marketValue: 0 }, [{ cost: 10, quantity: 1 }], CFG), null);
  assert.equal(findOpportunity(XANAX, [], CFG), null);
});

test('indexCatalogue normalise le catalogue et permet la recherche par nom', () => {
  const { byName, items } = indexCatalogue({
    206: { name: 'Xanax', type: 'Drug', market_value: '800000' },
    99: { name: 'Erotic DVD', type: 'Book', market_value: 4000000 },
    7: { type: 'Sans nom' },
  });
  assert.equal(items.length, 2);
  assert.equal(byName.get('xanax').id, 206);
  assert.equal(byName.get('xanax').marketValue, 800000);
});

/** Faux client API : sert un catalogue et des annonces fixes. */
function fakeApi({ items, listings = {}, failOn = null }) {
  const calls = [];
  return {
    calls,
    async get(section, selections) {
      calls.push(section);
      if (section === 'torn') return { items };
      const id = Number(section.split('/')[1]);
      if (failOn === id) throw new Error('Torn a refuse la requete');
      return listings[id] ?? { itemmarket: [], bazaar: [] };
    },
  };
}

const CATALOGUE = {
  206: { name: 'Xanax', type: 'Drug', market_value: 800000 },
  99: { name: 'Erotic DVD', type: 'Book', market_value: 4000000 },
};

test('scan resout la watchlist, classe les opportunites et signale les inconnus', async () => {
  const api = fakeApi({
    items: CATALOGUE,
    listings: {
      206: { itemmarket: [{ cost: 600000, quantity: 1 }], bazaar: [] },
      99: { itemmarket: [], bazaar: [{ cost: 3000000, quantity: 2 }] },
    },
  });
  const scanner = new MarketScanner(api, { ...CFG, watchlist: ['Xanax', 'erotic dvd', 'Objet Inexistant'] });
  const scan = await scanner.scan();

  assert.deepEqual(scan.unresolved, ['Objet Inexistant']);
  assert.equal(scan.scanned, 2);
  assert.deepEqual(scan.opportunities.map((o) => o.name), ['Erotic DVD', 'Xanax'], 'triees par marge totale');
  assert.equal(scan.opportunities[0].source, 'bazaar');
});

test('un objet en erreur n’interrompt pas le reste du scan', async () => {
  const api = fakeApi({
    items: CATALOGUE,
    listings: { 206: { itemmarket: [{ cost: 600000, quantity: 1 }] } },
    failOn: 99,
  });
  const scanner = new MarketScanner(api, { ...CFG, watchlist: ['Erotic DVD', 'Xanax'] });
  const scan = await scanner.scan();

  assert.equal(scan.opportunities.length, 1);
  assert.equal(scan.opportunities[0].name, 'Xanax');
  assert.equal(scan.errors.length, 1);
  assert.equal(scan.errors[0].name, 'Erotic DVD');
});

test('le catalogue n’est telecharge qu’une fois', async () => {
  const api = fakeApi({ items: CATALOGUE });
  const scanner = new MarketScanner(api, { ...CFG, watchlist: ['Xanax'] });
  await scanner.scan();
  await scanner.scan();
  assert.equal(api.calls.filter((c) => c === 'torn').length, 1);
});
