'use strict';

/**
 * Moteur de conseils : transforme un instantane en une liste d'actions
 * classees par urgence.
 *
 * Principe directeur du leveling sur Torn : l'XP vient des crimes (nerve) et
 * des attaques (energie). Toute regeneration perdue parce qu'une barre est
 * restee pleine est de l'XP perdue. Le coach optimise donc d'abord le
 * non-gaspillage, ensuite l'efficacite de la depense.
 *
 * Toutes les fonctions sont pures : aucun appel reseau, aucune horloge cachee.
 */

const DEFAULT_CONFIG = require('../config/coach.json');

const PRIORITY = {
  BLOCKED: 0,
  WASTING: 100,
  IMMINENT: 90,
  FREE_RESOURCE: 70,
  SPEND: 60,
  PREPARE: 40,
  UPKEEP: 30,
};

/**
 * @param {object} snapshot  sortie de buildSnapshot()
 * @param {object} [config]  surcharge partielle de config/coach.json
 * @returns {{blockers: object[], advice: object[], next: object|null}}
 */
function advise(snapshot, config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config, items: { ...DEFAULT_CONFIG.items, ...(config.items || {}) } };
  const blockers = findBlockers(snapshot);
  const advice = [];

  for (const rule of RULES) {
    const produced = rule(snapshot, cfg);
    if (!produced) continue;
    if (Array.isArray(produced)) advice.push(...produced.filter(Boolean));
    else advice.push(produced);
  }

  advice.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));

  // Tant qu'un bloqueur dur est actif (vol en cours, hopital), rien n'est
  // depensable : on garde les conseils mais aucun n'est "l'action suivante".
  const hardBlocked = blockers.some((b) => b.blocksSpending);
  return { blockers, advice, next: hardBlocked ? null : advice[0] ?? null };
}

function findBlockers(s) {
  const out = [];
  if (s.travel?.inFlight) {
    out.push({
      id: 'traveling',
      blocksSpending: true,
      title: `En vol vers ${s.travel.destination ?? 'destination inconnue'}`,
      seconds: s.travel.timeLeft,
    });
  }
  const state = s.player?.state;
  if (state === 'Hospital') {
    out.push({
      id: 'hospital',
      blocksSpending: true,
      title: 'A l’hopital',
      detail: s.player.statusDescription ?? null,
      seconds: s.player.stateUntil,
    });
  }
  if (state === 'Jail') {
    out.push({
      id: 'jail',
      blocksSpending: true,
      title: 'En prison',
      detail: s.player.statusDescription ?? null,
      seconds: s.player.stateUntil,
    });
  }
  return out;
}

/* ------------------------------------------------------------------ regles */

/** Nerve pleine ou presque : les crimes sont la source d'XP la plus reguliere. */
function nerveRule(s, cfg) {
  const bar = s.bars?.nerve;
  if (!bar) return null;
  if (bar.isFull) {
    return {
      id: 'nerve-full',
      priority: PRIORITY.WASTING,
      category: 'nerve',
      title: `Nerve pleine (${bar.current}/${bar.maximum}) — tu perds de la regen`,
      detail: 'Lance des crimes maintenant : chaque point de nerve non depense est de l’XP perdue.',
    };
  }
  if (bar.fullIn > 0 && bar.fullIn <= cfg.overflowWarningSeconds) {
    return {
      id: 'nerve-soon',
      priority: PRIORITY.IMMINENT,
      category: 'nerve',
      title: `Nerve pleine dans ${formatSeconds(bar.fullIn)}`,
      detail: `${bar.current}/${bar.maximum} — prevois une session de crimes avant le debordement.`,
    };
  }
  if (bar.ratio >= cfg.wasteWarningRatio) {
    return {
      id: 'nerve-high',
      priority: PRIORITY.SPEND,
      category: 'nerve',
      title: `Nerve a ${Math.round(bar.ratio * 100)}%`,
      detail: 'Bonne fenetre pour enchainer des crimes.',
    };
  }
  return null;
}

/** Energie pleine : attaques (XP + stats) ou gym (stats). */
function energyRule(s, cfg) {
  const bar = s.bars?.energy;
  if (!bar) return null;
  if (bar.isFull) {
    return {
      id: 'energy-full',
      priority: PRIORITY.WASTING,
      category: 'energy',
      title: `Energie pleine (${bar.current}/${bar.maximum}) — tu perds de la regen`,
      detail: 'Depense-la : attaques pour l’XP, gym pour les stats. Ne la laisse pas plafonner.',
    };
  }
  if (bar.fullIn > 0 && bar.fullIn <= cfg.overflowWarningSeconds) {
    return {
      id: 'energy-soon',
      priority: PRIORITY.IMMINENT,
      category: 'energy',
      title: `Energie pleine dans ${formatSeconds(bar.fullIn)}`,
      detail: `${bar.current}/${bar.maximum} — planifie ta depense maintenant.`,
    };
  }
  if (bar.ratio >= cfg.wasteWarningRatio) {
    return {
      id: 'energy-high',
      priority: PRIORITY.SPEND,
      category: 'energy',
      title: `Energie a ${Math.round(bar.ratio * 100)}%`,
      detail: 'Fenetre confortable pour une session gym ou attaques.',
    };
  }
  return null;
}

/**
 * Le happy conditionne les gains de gym : s'entrainer avec un happy au plancher
 * gaspille de l'energie. On previent seulement s'il reste de l'energie a depenser.
 */
function happyRule(s, cfg) {
  const happy = s.bars?.happy;
  const energy = s.bars?.energy;
  if (!happy || !energy) return null;
  if (happy.ratio >= cfg.happyFloorForGym) return null;
  if (energy.current < 10) return null;
  return {
    id: 'happy-low',
    priority: PRIORITY.PREPARE,
    category: 'happy',
    title: `Happy bas (${happy.current}/${happy.maximum})`,
    detail: 'Remonte le happy avant d’entrainer : a happy faible, la meme energie rapporte moins de stats.',
  };
}

/** Les refills quotidiens sont une barre entiere gratuite, une fois par jour. */
function refillRule(s) {
  const out = [];
  if (s.refills && s.refills.energyUsed === false) {
    out.push({
      id: 'refill-energy',
      priority: PRIORITY.FREE_RESOURCE,
      category: 'energy',
      title: 'Refill d’energie quotidien non utilise',
      detail: 'A consommer avant la remise a zero du jour — c’est une barre entiere gratuite.',
    });
  }
  if (s.refills && s.refills.nerveUsed === false) {
    out.push({
      id: 'refill-nerve',
      priority: PRIORITY.FREE_RESOURCE,
      category: 'nerve',
      title: 'Refill de nerve quotidien non utilise',
      detail: 'A consommer avant la remise a zero du jour.',
    });
  }
  return out;
}

/**
 * Cooldown drogue termine + energie basse : une prise d'energie remet la barre
 * a flot. Les valeurs viennent de config/coach.json, pas du code.
 */
function boosterRule(s, cfg) {
  const energy = s.bars?.energy;
  if (!energy) return null;
  if (s.cooldowns?.drug !== 0) return null;
  if (energy.ratio > 0.35) return null;
  const item = cfg.items?.xanax;
  if (!item) return null;
  return {
    id: 'drug-cooldown-clear',
    priority: PRIORITY.PREPARE,
    category: 'energy',
    title: `Cooldown drogue termine — ${item.label} disponible`,
    detail: `Energie a ${Math.round(energy.ratio * 100)}% : un ${item.label} (~+${item.energy} energie) relance la session.`,
  };
}

/** Un cours d'education termine ne se reinscrit pas tout seul. */
function educationRule(s) {
  const edu = s.education;
  if (!edu) return null;
  if (edu.current === null && edu.timeLeft === null) return null;
  const idle = !edu.current || edu.timeLeft === 0;
  if (!idle) return null;
  return {
    id: 'education-idle',
    priority: PRIORITY.UPKEEP,
    category: 'upkeep',
    title: 'Aucun cours en cours',
    detail: 'Reinscris-toi : les cours tournent en arriere-plan et ne coutent aucune energie.',
  };
}

/** Une chaine active expire vite et vaut beaucoup d'XP : elle passe devant. */
function chainRule(s) {
  const chain = s.chain;
  if (!chain || !chain.current || chain.current < 10) return null;
  if (!chain.timeout || chain.timeout <= 0) return null;
  return {
    id: 'chain-active',
    priority: PRIORITY.WASTING + 5,
    category: 'chain',
    title: `Chaine active : ${chain.current} hits, expire dans ${formatSeconds(chain.timeout)}`,
    detail: 'Priorite absolue tant qu’elle tient — c’est le meilleur rendement XP de la faction.',
  };
}

const RULES = [chainRule, nerveRule, energyRule, happyRule, refillRule, boosterRule, educationRule];

/* ------------------------------------------------------------------ helpers */

function formatSeconds(total) {
  if (total === null || total === undefined || total < 0) return '?';
  const s = Math.floor(total);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m${s % 60 ? ` ${s % 60}s` : ''}`;
  const h = Math.floor(m / 60);
  return `${h}h${m % 60 ? ` ${m % 60}m` : ''}`;
}

module.exports = { advise, formatSeconds, PRIORITY, DEFAULT_CONFIG };
