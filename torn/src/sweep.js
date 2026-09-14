'use strict';

/**
 * Balayage continu de l'Item Market.
 *
 * CONTRAINTE : il n'existe pas d'endpoint listant toutes les annonces du jeu en
 * une fois. Chaque objet demande sa propre requete, et Torn plafonne a 100
 * requetes/minute par joueur. Un catalogue de ~900 objets represente donc une
 * dizaine de minutes par cycle complet.
 *
 * D'ou ce choix : au lieu d'un scan unique qui fait attendre, un balayage en
 * boucle qui met a jour un tableau vivant. Les affaires apparaissent au fil de
 * l'eau et sont rafraichies a chaque passage.
 *
 * PERIMETRE : lecture seule. Le module produit des liens d'achat ; c'est
 * l'humain qui achete. L'API n'expose aucun endpoint d'achat, et piloter le site
 * pour cliquer a sa place est un motif de bannissement.
 */

const DEFAULT_CONFIG = require('../config/coach.json');
const { findOpportunity, normalizeListings, indexCatalogue } = require('./market');

/**
 * Selectionne les objets qui valent la peine d'etre balayes.
 * Chercher 20 % de marge sur un objet a 500 $ consomme une requete pour 100 $
 * de gain theorique : le plancher de valeur elimine ce bruit.
 */
function selectScannableItems(items, cfg) {
  const floor = cfg.minMarketValue ?? 0;
  const selected = items
    .filter((item) => item.marketValue >= floor)
    .sort((a, b) => b.marketValue - a.marketValue);
  const cap = cfg.maxItems ?? 0;
  return cap > 0 ? selected.slice(0, cap) : selected;
}

class MarketSweeper {
  constructor(api, config = {}) {
    this.api = api;
    this.config = { ...DEFAULT_CONFIG.sweep, ...config };
    this.opportunities = new Map(); // itemId -> opportunite
    this.queue = [];
    this.cursor = 0;
    this.running = false;
    this.scannedThisCycle = 0;
    this.cycles = 0;
    this.cycleStartedAt = null;
    this.lastError = null;
    this.itemCount = 0;
  }

  async loadQueue() {
    const raw = await this.api.get('torn', ['items']);
    const { items } = indexCatalogue(raw?.items);
    this.queue = selectScannableItems(items, this.config);
    this.itemCount = this.queue.length;
    this.cursor = 0;
    this.cycleStartedAt = Date.now();
    return this.queue.length;
  }

  /** Un objet : requete, evaluation, mise a jour du tableau. */
  async scanOne(item) {
    const raw = await this.api.get(`market/${item.id}`, ['itemmarket', 'bazaar']);
    const listings = [
      ...normalizeListings(raw?.itemmarket, 'itemmarket'),
      ...normalizeListings(raw?.bazaar, 'bazaar'),
    ];
    const opportunity = findOpportunity(item, listings, this.config);

    if (opportunity) this.opportunities.set(item.id, { ...opportunity, foundAt: Date.now() });
    // Plus d'affaire sur cet objet : on retire l'entree devenue fausse plutot
    // que de laisser une annonce disparue dans le tableau.
    else this.opportunities.delete(item.id);

    return opportunity;
  }

  /** Retire les entrees qu'aucun passage recent n'a confirmees. */
  pruneStale(now = Date.now()) {
    const ttl = (this.config.staleSeconds ?? 1800) * 1000;
    for (const [id, o] of this.opportunities) {
      if (now - o.foundAt > ttl) this.opportunities.delete(id);
    }
  }

  /** @param {number} [maxSteps] borne le nombre d'objets traites (tests). */
  async tick(maxSteps = 1) {
    for (let i = 0; i < maxSteps; i += 1) {
      if (this.queue.length === 0) return;
      const item = this.queue[this.cursor];
      try {
        await this.scanOne(item);
        this.lastError = null;
      } catch (err) {
        // Un objet en echec ne doit pas arreter un balayage de plusieurs minutes.
        this.lastError = { item: item.name, message: err.message, at: Date.now() };
      }

      this.scannedThisCycle += 1;
      this.cursor += 1;
      if (this.cursor >= this.queue.length) {
        this.cursor = 0;
        this.cycles += 1;
        this.scannedThisCycle = 0;
        this.cycleStartedAt = Date.now();
      }
    }
    this.pruneStale();
  }

  /** Boucle continue. Le limiteur de TornApi impose deja le rythme. */
  async start() {
    if (this.running) return;
    this.running = true;
    if (this.queue.length === 0) await this.loadQueue();

    (async () => {
      while (this.running) {
        await this.tick(1);
      }
    })().catch((err) => {
      this.running = false;
      this.lastError = { item: null, message: err.message, at: Date.now() };
    });
  }

  stop() {
    this.running = false;
  }

  /** Etat consommable par la page : affaires triees par marge totale. */
  get state() {
    const opportunities = [...this.opportunities.values()].sort((a, b) => b.totalProfit - a.totalProfit);
    return {
      running: this.running,
      opportunities,
      itemCount: this.itemCount,
      scannedThisCycle: this.scannedThisCycle,
      cycles: this.cycles,
      cycleStartedAt: this.cycleStartedAt,
      lastError: this.lastError,
      config: {
        minDiscountPercent: this.config.minDiscountPercent,
        minNetMarginPercent: this.config.minNetMarginPercent,
        salesFeePercent: this.config.salesFeePercent,
        minMarketValue: this.config.minMarketValue,
      },
    };
  }
}

module.exports = { MarketSweeper, selectScannableItems };
