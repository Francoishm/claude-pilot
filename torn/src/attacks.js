'use strict';

/**
 * Analyse du journal d'attaques.
 *
 * POURQUOI CE MODULE EXISTE : sur Torn, l'XP est volontairement cachee. Il
 * n'existe aucune table publique d'XP par niveau et l'API n'expose aucun champ
 * d'experience — c'est un choix de design du jeu, pas une lacune de l'API.
 * On ne peut donc pas repondre exactement a "combien de joueurs battre".
 *
 * Ce qu'on peut faire, et que fait ce module : mesurer si tes attaques sont du
 * *bon type*. L'XP d'une attaque depend du NIVEAU de la cible et de l'issue
 * choisie (laisser sur place > voler > hospitaliser). Une attaque gagnee mal
 * conclue est de l'energie depensee pour une fraction de l'XP.
 */

const DEFAULT_CONFIG = require('../config/coach.json');

/**
 * Issues d'attaque, classees par rendement XP.
 * `leave` (result "Attacked") donne le maximum ; `mug` et `hosp` le reduisent
 * nettement. Voir README pour les sources.
 */
const RESULT_CLASSES = {
  attacked: 'leave',
  mugged: 'mug',
  hospitalized: 'hosp',
  lost: 'loss',
  stalemate: 'loss',
  escape: 'other',
  escaped: 'other',
  timeout: 'other',
  assist: 'other',
  special: 'other',
  looted: 'mug',
  interrupted: 'other',
};

function classifyResult(result) {
  if (!result) return 'other';
  return RESULT_CLASSES[String(result).toLowerCase()] ?? 'other';
}

function num(v) {
  const n = typeof v === 'string' ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) ? n : null;
}

/**
 * Normalise le journal, quelle que soit la forme renvoyee (objet indexe en v1,
 * tableau en v2) et le nom du champ de respect.
 */
function normalizeAttacks(raw, myId = null) {
  const source = raw?.attacks ?? raw;
  if (!source || typeof source !== 'object') return [];
  const rows = Array.isArray(source) ? source : Object.values(source);

  return rows
    .map((a) => {
      if (!a || typeof a !== 'object') return null;
      const attackerId = num(a.attacker_id);
      // Le journal contient aussi les attaques *subies* : on ne garde que
      // celles ou l'on est l'attaquant.
      if (myId !== null && attackerId !== null && attackerId !== myId) return null;

      return {
        at: (num(a.timestamp_ended) ?? num(a.timestamp_started) ?? 0) * 1000,
        defenderId: num(a.defender_id),
        defenderName: a.defender_name ?? null,
        defenderLevel: num(a.defender_level),
        result: a.result ?? null,
        class: classifyResult(a.result),
        respect: num(a.respect_gain) ?? num(a.respect) ?? 0,
        chainBonus: Boolean(a.modifiers?.chainBonus && a.modifiers.chainBonus > 1),
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.at - b.at);
}

/**
 * @param {object[]} attacks  sortie de normalizeAttacks
 * @param {object} [cfg]      section `leveling` de la config
 */
function summarizeAttacks(attacks, cfg = DEFAULT_CONFIG.leveling) {
  const counts = { leave: 0, mug: 0, hosp: 0, loss: 0, other: 0 };
  let respect = 0;
  let levelSum = 0;
  let levelKnown = 0;

  for (const a of attacks) {
    counts[a.class] = (counts[a.class] ?? 0) + 1;
    respect += a.respect;
    if (a.defenderLevel !== null) {
      levelSum += a.defenderLevel;
      levelKnown += 1;
    }
  }

  const won = counts.leave + counts.mug + counts.hosp;
  const suboptimal = counts.mug + counts.hosp;

  return {
    total: attacks.length,
    from: attacks[0]?.at ?? null,
    to: attacks[attacks.length - 1]?.at ?? null,
    counts,
    won,
    // Part des victoires conclues de la maniere la plus rentable en XP.
    leaveRatio: won > 0 ? counts.leave / won : null,
    suboptimal,
    respect: Math.round(respect * 100) / 100,
    averageDefenderLevel: levelKnown > 0 ? Math.round((levelSum / levelKnown) * 10) / 10 : null,
    defenderLevelsKnown: levelKnown,
    benchmark: cfg?.attacksToLevel15 ?? null,
  };
}

/**
 * Conseils d'optimisation tires du journal. Chaque regle vise une perte
 * concrete et mesurable, pas une generalite.
 */
function attackAdvice(summary, cfg = DEFAULT_CONFIG.leveling) {
  const out = [];
  if (summary.won === 0) {
    out.push({
      id: 'no-wins',
      title: 'Aucune attaque gagnee sur la periode',
      detail: 'Le journal ne contient pas de victoire : rien a optimiser encore.',
    });
    return out;
  }

  if (summary.suboptimal > 0) {
    const pct = Math.round((summary.suboptimal / summary.won) * 100);
    out.push({
      id: 'not-leaving',
      title: `${summary.suboptimal} victoire(s) sur ${summary.won} (${pct}%) conclues en vol ou hospitalisation`,
      detail:
        'Laisser la cible sur place donne le maximum d’XP ; voler ou hospitaliser le reduit fortement. ' +
        'Sur une cible de leveling, hospitaliser bloque aussi la cible pour les autres joueurs.',
    });
  }

  const minLevel = cfg?.minTargetLevel ?? 0;
  if (summary.averageDefenderLevel !== null && minLevel > 0 && summary.averageDefenderLevel < minLevel) {
    out.push({
      id: 'targets-too-low',
      title: `Niveau moyen des cibles : ${summary.averageDefenderLevel}`,
      detail:
        `L’XP d’une attaque depend du niveau de la cible, pas de ses stats. Vise des cibles ` +
        `de niveau eleve mais faibles en combat (au-dessus de ${minLevel}) plutot que des joueurs bas niveau.`,
    });
  } else if (summary.averageDefenderLevel === null) {
    out.push({
      id: 'levels-unknown',
      title: 'Niveau des cibles inconnu',
      detail: 'Relance avec --enrich pour recuperer le niveau des defenseurs et verifier que tu vises assez haut.',
    });
  }

  if (summary.benchmark) {
    const remaining = Math.max(0, summary.benchmark - summary.counts.leave);
    out.push({
      id: 'benchmark',
      title: `${summary.counts.leave} attaque(s) "laissee sur place" — repere communautaire : ~${summary.benchmark} pour le niveau 15`,
      detail:
        remaining > 0
          ? `Environ ${remaining} restantes a ce rythme. Repere indicatif : l’XP etant cachee, ce n’est pas une garantie.`
          : 'Tu as depasse le repere : le niveau 15 devrait etre proche ou atteint.',
    });
  }

  return out;
}

class AttackAnalyzer {
  constructor(api, config = {}) {
    this.api = api;
    this.config = { ...DEFAULT_CONFIG.leveling, ...config };
    this.levelCache = new Map();
  }

  /** @param {number} [sinceMs] limite basse ; l'API renvoie les 100 dernieres. */
  async fetch(sinceMs = 0) {
    const params = sinceMs > 0 ? { from: Math.floor(sinceMs / 1000) } : {};
    const [raw, me] = await Promise.all([
      this.api.get('user', ['attacks'], params),
      this.api.get('user', ['basic']),
    ]);
    return normalizeAttacks(raw, num(me?.player_id));
  }

  /**
   * Complete le niveau des defenseurs (un appel API par joueur distinct).
   * Plafonne pour ne pas transformer une analyse en centaines de requetes.
   */
  async enrich(attacks) {
    const ids = [...new Set(attacks.map((a) => a.defenderId).filter((id) => id !== null))];
    const budget = this.config.maxEnrichLookups ?? 25;

    for (const id of ids.slice(0, budget)) {
      if (this.levelCache.has(id)) continue;
      try {
        const profile = await this.api.get(`user/${id}`, ['profile']);
        this.levelCache.set(id, num(profile?.level));
      } catch {
        // Un profil inaccessible ne doit pas faire echouer l'analyse.
        this.levelCache.set(id, null);
      }
    }

    return attacks.map((a) => ({
      ...a,
      defenderLevel: a.defenderLevel ?? this.levelCache.get(a.defenderId) ?? null,
    }));
  }

  async analyze({ sinceMs = 0, enrich = false } = {}) {
    let attacks = await this.fetch(sinceMs);
    if (enrich) attacks = await this.enrich(attacks);
    const summary = summarizeAttacks(attacks, this.config);
    return { attacks, summary, advice: attackAdvice(summary, this.config) };
  }
}

module.exports = { AttackAnalyzer, normalizeAttacks, summarizeAttacks, attackAdvice, classifyResult };
