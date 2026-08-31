'use strict';

/**
 * Normalise la reponse brute de l'API Torn en un instantane stable,
 * independant des variations de forme entre versions de l'API.
 *
 * Toutes les fonctions ici sont pures : elles sont testables sans reseau.
 */

const BAR_NAMES = ['energy', 'nerve', 'happy', 'life'];

function normalizeBar(name, raw) {
  if (!raw || typeof raw !== 'object') return null;
  const current = num(raw.current);
  const maximum = num(raw.maximum);
  if (current === null || maximum === null) return null;

  // `fulltime` = secondes avant la barre pleine (0 si deja pleine).
  const fulltime = num(raw.fulltime) ?? estimateFulltime(raw, current, maximum);

  return {
    name,
    current,
    maximum,
    ratio: maximum > 0 ? current / maximum : 0,
    increment: num(raw.increment) ?? 0,
    interval: num(raw.interval) ?? 0,
    // Secondes avant le prochain tick de regen.
    nextTickIn: num(raw.ticktime) ?? null,
    fullIn: fulltime,
    isFull: current >= maximum,
  };
}

/** Repli si l'API n'a pas fourni `fulltime`. */
function estimateFulltime(raw, current, maximum) {
  const increment = num(raw.increment);
  const interval = num(raw.interval);
  if (!increment || !interval || current >= maximum) return 0;
  const ticks = Math.ceil((maximum - current) / increment);
  return ticks * interval - (interval - (num(raw.ticktime) ?? interval));
}

function num(v) {
  const n = typeof v === 'string' ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) ? n : null;
}

/**
 * @param {object} raw    payload de TornApi#fetchPlayer()
 * @param {number} [now]  epoch ms, injectable pour les tests
 */
function buildSnapshot(raw, now = Date.now()) {
  const bars = {};
  // Selon la version de l'API les barres sont a la racine ou sous `bars`.
  const barSource = raw?.bars ?? raw ?? {};
  for (const name of BAR_NAMES) {
    const bar = normalizeBar(name, barSource[name]);
    if (bar) bars[name] = bar;
  }

  const travel = raw?.travel ?? {};
  const cooldowns = raw?.cooldowns ?? {};
  const refills = raw?.refills ?? {};
  const education = raw?.education ?? {};

  return {
    fetchedAt: now,
    serverTime: num(raw?.server_time),
    player: {
      id: num(raw?.player_id),
      name: raw?.name ?? null,
      level: num(raw?.level),
      // status.state vaut 'Okay', 'Hospital', 'Jail', 'Traveling', 'Abroad'.
      state: raw?.status?.state ?? null,
      statusDescription: raw?.status?.description ?? null,
      // Secondes restantes en hopital / prison (0 si libre).
      stateUntil: num(raw?.status?.until) ?? 0,
    },
    bars,
    chain: raw?.chain
      ? { current: num(raw.chain.current), maximum: num(raw.chain.maximum), timeout: num(raw.chain.timeout) }
      : null,
    travel: {
      // `time_left` > 0 signifie que l'avion est en vol.
      inFlight: num(travel.time_left) > 0,
      destination: travel.destination ?? null,
      timeLeft: num(travel.time_left) ?? 0,
    },
    cooldowns: {
      drug: num(cooldowns.drug) ?? 0,
      medical: num(cooldowns.medical) ?? 0,
      booster: num(cooldowns.booster) ?? 0,
    },
    refills: {
      energyUsed: Boolean(refills.energy_refill_used),
      nerveUsed: Boolean(refills.nerve_refill_used),
      tokenUsed: Boolean(refills.token_refill_used),
    },
    education: {
      // `time_left` a 0 avec un cours en cours = cours termine, a reinscrire.
      current: num(education.education_current),
      timeLeft: num(education.education_timeleft),
    },
    money: {
      cash: num(raw?.money_onhand),
      points: num(raw?.points),
    },
  };
}

module.exports = { buildSnapshot, normalizeBar, BAR_NAMES };
