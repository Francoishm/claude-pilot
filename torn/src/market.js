'use strict';

/**
 * Scanner d'opportunites sur l'Item Market.
 *
 * PERIMETRE : lecture seule. Ce module lit les annonces publiques via l'API
 * Torn et signale les ecarts de prix interessants. Il n'achete rien et ne peut
 * rien acheter : l'API n'expose aucun endpoint d'achat, et automatiser un achat
 * en pilotant le site est un motif de bannissement. Le script trouve l'affaire,
 * l'humain clique.
 *
 * Mise en garde importante sur `market_value` : c'est une moyenne glissante,
 * donc un retardataire. Une annonce 30 % sous cette valeur peut signifier une
 * bonne affaire... ou un prix de marche qui vient de s'effondrer. C'est un
 * signal a verifier, pas une certitude.
 */

const DEFAULT_CONFIG = require('../config/coach.json');

/** Normalise les annonces, quelle que soit la casse des champs renvoyes. */
function normalizeListings(raw, source) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((entry) => {
      const cost = num(entry?.cost ?? entry?.price);
      const quantity = num(entry?.quantity ?? entry?.amount) ?? 1;
      if (cost === null || cost <= 0 || quantity <= 0) return null;
      return { cost, quantity, source };
    })
    .filter(Boolean);
}

function num(v) {
  const n = typeof v === 'string' ? Number(v.replace(/[^0-9.-]/g, '')) : v;
  return typeof n === 'number' && Number.isFinite(n) ? n : null;
}

/**
 * Compare la meilleure annonce a la valeur de marche de l'objet.
 *
 * @param {{id:number,name:string,marketValue:number}} item
 * @param {Array<{cost:number,quantity:number,source:string}>} listings
 * @param {object} cfg  section `market` de la config
 * @returns {object|null} l'opportunite, ou null si rien ne passe les seuils
 */
function findOpportunity(item, listings, cfg) {
  if (!item?.marketValue || item.marketValue <= 0) return null;
  const sorted = [...listings].sort((a, b) => a.cost - b.cost);
  const best = sorted[0];
  if (!best) return null;

  const profitPerUnit = item.marketValue - best.cost;
  if (profitPerUnit <= 0) return null;

  const discountPercent = (profitPerUnit / item.marketValue) * 100;
  if (discountPercent < (cfg.minDiscountPercent ?? 0)) return null;
  if (profitPerUnit < (cfg.minProfitPerUnit ?? 0)) return null;

  // Combien d'unites la tresorerie autorise, si une limite est fixee.
  const budget = cfg.maxCashPerBuy || 0;
  const affordable = budget > 0 ? Math.min(best.quantity, Math.floor(budget / best.cost)) : best.quantity;
  if (affordable < 1) return null;

  return {
    itemId: item.id,
    name: item.name,
    cost: best.cost,
    marketValue: item.marketValue,
    quantity: best.quantity,
    affordable,
    source: best.source,
    profitPerUnit,
    totalProfit: profitPerUnit * affordable,
    discountPercent: Math.round(discountPercent * 10) / 10,
  };
}

/** Indexe le catalogue Torn par nom normalise, pour resoudre la watchlist. */
function indexCatalogue(rawItems) {
  const byName = new Map();
  const items = [];
  for (const [id, entry] of Object.entries(rawItems || {})) {
    const item = {
      id: Number(id),
      name: entry?.name ?? null,
      type: entry?.type ?? null,
      marketValue: num(entry?.market_value) ?? 0,
    };
    if (!item.name) continue;
    items.push(item);
    byName.set(item.name.toLowerCase(), item);
  }
  return { byName, items };
}

class MarketScanner {
  /**
   * @param {import('./api').TornApi} api
   * @param {object} [config] surcharge de la section `market`
   */
  constructor(api, config = {}) {
    this.api = api;
    this.config = { ...DEFAULT_CONFIG.market, ...config };
    this.catalogue = null;
  }

  /** Le catalogue est volumineux : on ne le charge qu'une fois par process. */
  async loadCatalogue() {
    if (this.catalogue) return this.catalogue;
    const raw = await this.api.get('torn', ['items']);
    this.catalogue = indexCatalogue(raw?.items);
    return this.catalogue;
  }

  /** @returns {{items: object[], unresolved: string[]}} */
  async resolveWatchlist(names = this.config.watchlist) {
    const { byName } = await this.loadCatalogue();
    const items = [];
    const unresolved = [];
    for (const name of names || []) {
      const item = byName.get(String(name).toLowerCase());
      if (item) items.push(item);
      else unresolved.push(name);
    }
    return { items, unresolved };
  }

  async listingsFor(itemId) {
    const raw = await this.api.get(`market/${itemId}`, ['itemmarket', 'bazaar']);
    return [
      ...normalizeListings(raw?.itemmarket, 'itemmarket'),
      ...normalizeListings(raw?.bazaar, 'bazaar'),
    ];
  }

  /**
   * Un passage complet sur la watchlist.
   * Le limiteur de TornApi espace deja les requetes : une watchlist longue
   * rallonge simplement le scan, elle ne declenche pas de rate limit.
   */
  async scan() {
    const { items, unresolved } = await this.resolveWatchlist();
    const opportunities = [];
    const errors = [];

    for (const item of items) {
      try {
        const listings = await this.listingsFor(item.id);
        const opportunity = findOpportunity(item, listings, this.config);
        if (opportunity) opportunities.push(opportunity);
      } catch (err) {
        // Un objet en echec ne doit pas interrompre le reste du scan.
        errors.push({ name: item.name, message: err.message });
      }
    }

    opportunities.sort((a, b) => b.totalProfit - a.totalProfit);
    return { opportunities, unresolved, errors, scanned: items.length };
  }
}

module.exports = { MarketScanner, findOpportunity, normalizeListings, indexCatalogue };
