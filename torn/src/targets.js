'use strict';

/**
 * Estimation des stats de combat d'une cible, et selection de cibles de leveling.
 *
 * CONTRAINTE DE DEPART : les battle stats d'autrui sont des donnees PRIVEES.
 * Aucune cle API, quel que soit son niveau d'acces, ne les expose. Il n'existe
 * donc aucun moyen direct de demander "les comptes niveau 20+ sous 400 stats".
 *
 * CE QUI EST MESURABLE : le modificateur Fair Fight renvoye par le jeu apres
 * chaque attaque depend du rapport de force. En connaissant son propre score, on
 * en deduit celui de l'adversaire :
 *
 *   BSS            = somme des racines carrees des 4 stats, arrondie
 *   DefenderScore  = (FF - 1) x 3/8 x AttackerScore
 *   DefenderStats ~= DefenderScore^2 / 4        (si la cible est equilibree)
 *
 * Deux limites a ne jamais perdre de vue :
 *  - la derniere etape suppose une cible equilibree. Une cible desequilibree a
 *    PLUS de stats totales pour le meme score : l'estimation est un plancher.
 *  - FF plafonne par le bas a 1. A FF = 1, la cible est simplement "beaucoup
 *    plus faible que moi" : la formule ne resout plus rien sous ce seuil.
 *
 * Et surtout : le Fair Fight n'existe que pour les joueurs que tu as DEJA
 * attaques. Ce module lit un historique, il n'explore pas la base joueurs.
 */

const DEFAULT_CONFIG = require('../config/coach.json');
const { normalizeAttacks } = require('./attacks');

/** Battle Stat Score : somme des racines carrees des quatre stats. */
function battleStatScore(stats) {
  const parts = [stats?.strength, stats?.defense, stats?.speed, stats?.dexterity];
  let total = 0;
  for (const raw of parts) {
    const v = typeof raw === 'string' ? Number(raw) : raw;
    if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) return null;
    total += Math.sqrt(v);
  }
  return Math.round(total);
}

/**
 * @param {number} fairFight  modificateur renvoye par le jeu (>= 1)
 * @param {number} attackerScore  BSS de l'attaquant
 * @returns {{score:number, stats:number, resolved:boolean}|null}
 */
function estimateFromFairFight(fairFight, attackerScore) {
  if (typeof fairFight !== 'number' || !Number.isFinite(fairFight)) return null;
  if (typeof attackerScore !== 'number' || attackerScore <= 0) return null;

  // FF <= 1 : la cible est sous le seuil de resolution de la mesure.
  if (fairFight <= 1) return { score: 0, stats: 0, resolved: false };

  const score = (fairFight - 1) * (3 / 8) * attackerScore;
  return {
    score: Math.round(score * 100) / 100,
    stats: Math.round((score * score) / 4),
    resolved: true,
  };
}

/** Le FF vit sous des noms differents selon la version de l'API. */
function readFairFight(attack) {
  const raw = attack?.modifiers?.fairFight ?? attack?.modifiers?.fair_fight ?? attack?.fair_fight;
  const v = typeof raw === 'string' ? Number(raw) : raw;
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/**
 * Regroupe les attaques par defenseur et retient le FF le plus eleve observe.
 * Le maximum est le plus informatif : un FF plus bas peut venir d'une attaque
 * ou l'adversaire etait affaibli.
 */
function candidatesFromAttacks(rawAttacks, myId) {
  const normalized = normalizeAttacks(rawAttacks, myId);
  const source = rawAttacks?.attacks ?? rawAttacks;
  const rows = Array.isArray(source) ? source : Object.values(source || {});

  const ffById = new Map();
  for (const row of rows) {
    const id = Number(row?.defender_id);
    const ff = readFairFight(row);
    if (!Number.isFinite(id) || ff === null) continue;
    if (!ffById.has(id) || ff > ffById.get(id)) ffById.set(id, ff);
  }

  const byId = new Map();
  for (const a of normalized) {
    if (a.defenderId === null) continue;
    const existing = byId.get(a.defenderId);
    if (existing) {
      existing.attacks += 1;
      existing.lastAttack = Math.max(existing.lastAttack, a.at);
      continue;
    }
    byId.set(a.defenderId, {
      id: a.defenderId,
      name: a.defenderName,
      level: a.defenderLevel,
      fairFight: ffById.get(a.defenderId) ?? null,
      attacks: 1,
      lastAttack: a.at,
    });
  }
  return [...byId.values()];
}

/**
 * Applique les filtres de selection.
 * Une cible dont les stats ne sont pas estimables n'est pas eliminee en
 * silence : elle est renvoyee avec `stats: null` et signalee comme inconnue.
 */
function filterTargets(candidates, cfg) {
  const minLevel = cfg.minLevel ?? 0;
  const maxStats = cfg.maxStats ?? Infinity;
  const excludedStates = (cfg.excludeStates ?? []).map((s) => s.toLowerCase());
  const wantedRanks = (cfg.ranks ?? []).map((r) => r.toLowerCase());
  const maxIdleDays = cfg.maxIdleDays ?? null;

  const kept = [];
  const rejected = [];

  for (const c of candidates) {
    if (c.level !== null && c.level < minLevel) {
      rejected.push({ ...c, reason: `niveau ${c.level} < ${minLevel}` });
      continue;
    }
    // Un compte en prison federale est banni : inattaquable, jamais une cible.
    if (c.state && excludedStates.includes(c.state.toLowerCase())) {
      rejected.push({ ...c, reason: `statut ${c.state} — inattaquable` });
      continue;
    }
    // Le rang derive du niveau, des crimes, du networth et des stats : un rang
    // bas a niveau eleve trahit des stats minimales.
    if (wantedRanks.length > 0) {
      const rank = (c.rank ?? '').toLowerCase();
      if (!rank || !wantedRanks.some((r) => rank.includes(r))) {
        rejected.push({ ...c, reason: `rang "${c.rank ?? 'inconnu'}" hors filtre` });
        continue;
      }
    }
    if (maxIdleDays !== null && c.lastActionDays !== null && c.lastActionDays > maxIdleDays) {
      rejected.push({ ...c, reason: `inactif depuis ${c.lastActionDays}j` });
      continue;
    }
    if (c.stats !== null && c.stats > maxStats) {
      rejected.push({ ...c, reason: `stats estimees ~${c.stats} > ${maxStats}` });
      continue;
    }
    kept.push(c);
  }

  // Les cibles les plus hautes en niveau d'abord : l'XP suit le niveau.
  kept.sort((a, b) => (b.level ?? 0) - (a.level ?? 0));
  return { kept, rejected };
}

class TargetFinder {
  constructor(api, config = {}) {
    this.api = api;
    this.config = { ...DEFAULT_CONFIG.targets, ...config };
  }

  /** Mon propre BSS : mes stats sont accessibles avec ma propre cle. */
  async myScore() {
    const stats = await this.api.get('user', ['battlestats']);
    return battleStatScore(stats);
  }

  async profile(id) {
    const p = await this.api.get(`user/${id}`, ['profile']);
    return {
      level: Number.isFinite(Number(p?.level)) ? Number(p.level) : null,
      name: p?.name ?? null,
      rank: p?.rank ?? null,
      lastActionDays: Number.isFinite(Number(p?.last_action?.timestamp))
        ? Math.floor((Date.now() / 1000 - Number(p.last_action.timestamp)) / 86400)
        : null,
      faction: p?.faction?.faction_name || null,
      // "Federal" = compte banni : injoignable, il ne peut pas etre attaque.
      state: p?.status?.state ?? null,
    };
  }

  /**
   * @param {object} opts
   * @param {number[]} [opts.extraIds]  identifiants issus d'une liste communautaire
   */
  async find({ extraIds = [] } = {}) {
    const [attackScore, me] = await Promise.all([this.myScore(), this.api.get('user', ['basic'])]);
    if (attackScore === null) {
      throw new Error('Impossible de lire tes battle stats : la cle doit autoriser la selection `battlestats`.');
    }

    const rawAttacks = await this.api.get('user', ['attacks']);
    const candidates = candidatesFromAttacks(rawAttacks, Number(me?.player_id));

    for (const id of extraIds) {
      if (!candidates.some((c) => c.id === id)) {
        candidates.push({ id, name: null, level: null, fairFight: null, attacks: 0, lastAttack: null });
      }
    }

    const budget = this.config.maxLookups ?? 25;
    const enriched = [];
    for (const c of candidates.slice(0, budget)) {
      let profile = {};
      try {
        profile = await this.profile(c.id);
      } catch {
        // Profil inaccessible : la cible reste dans la liste, sans details.
      }
      const estimate = c.fairFight !== null ? estimateFromFairFight(c.fairFight, attackScore) : null;
      enriched.push({
        ...c,
        name: profile.name ?? c.name,
        level: profile.level ?? c.level,
        rank: profile.rank ?? null,
        lastActionDays: profile.lastActionDays ?? null,
        faction: profile.faction ?? null,
        state: profile.state ?? null,
        stats: estimate?.resolved ? estimate.stats : null,
        // FF au plancher : la cible est mesurablement plus faible que moi.
        belowResolution: estimate ? !estimate.resolved : false,
      });
    }

    const { kept, rejected } = filterTargets(enriched, this.config);
    return {
      attackScore,
      inspected: enriched.length,
      truncated: candidates.length > budget,
      targets: kept,
      rejected,
    };
  }
}

module.exports = {
  TargetFinder,
  battleStatScore,
  estimateFromFairFight,
  candidatesFromAttacks,
  filterTargets,
  readFairFight,
};
