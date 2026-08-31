'use strict';

/**
 * Historique local (JSONL) et mesure du gaspillage.
 *
 * L'interet : au lieu d'estimer avec une formule, on mesure sur tes propres
 * donnees combien d'energie et de nerve partent a la poubelle parce qu'une
 * barre est restee pleine entre deux relevés.
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_FILE = path.join(__dirname, '..', 'data', 'history.jsonl');

/** Ligne compacte : on ne stocke que ce qui sert aux statistiques. */
function toRecord(snapshot) {
  const bar = (n) => {
    const b = snapshot.bars?.[n];
    return b ? { c: b.current, m: b.maximum, i: b.increment, t: b.interval } : null;
  };
  return {
    ts: snapshot.fetchedAt,
    level: snapshot.player?.level ?? null,
    state: snapshot.player?.state ?? null,
    energy: bar('energy'),
    nerve: bar('nerve'),
    happy: bar('happy'),
  };
}

class Tracker {
  constructor({ file = DEFAULT_FILE } = {}) {
    this.file = file;
  }

  record(snapshot) {
    const line = `${JSON.stringify(toRecord(snapshot))}\n`;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.appendFileSync(this.file, line);
  }

  load() {
    if (!fs.existsSync(this.file)) return [];
    return fs
      .readFileSync(this.file, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => {
        try {
          return JSON.parse(l);
        } catch {
          return null; // ligne tronquee (arret brutal) : on l'ignore.
        }
      })
      .filter(Boolean);
  }

  /** @param {number} [sinceMs] ne considere que les releves plus recents. */
  report(sinceMs = 0) {
    const records = this.load().filter((r) => r.ts >= sinceMs);
    return summarize(records);
  }
}

/**
 * Estime la regen perdue entre deux releves consecutifs.
 * Une barre pleine aux deux extremites a gaspille tout ce qu'elle aurait
 * regenere pendant l'intervalle.
 */
function wastedBetween(prev, next, key) {
  const a = prev?.[key];
  const b = next?.[key];
  if (!a || !b || !a.i || !a.t) return 0;
  if (a.c < a.m || b.c < b.m) return 0;
  const gapSeconds = (next.ts - prev.ts) / 1000;
  if (gapSeconds <= 0) return 0;
  return (gapSeconds / a.t) * a.i;
}

function summarize(records) {
  const empty = {
    samples: records.length,
    from: null,
    to: null,
    wasted: { energy: 0, nerve: 0 },
    fullSeconds: { energy: 0, nerve: 0 },
    levelUps: [],
  };
  if (records.length === 0) return empty;

  const out = {
    ...empty,
    from: records[0].ts,
    to: records[records.length - 1].ts,
    wasted: { energy: 0, nerve: 0 },
    fullSeconds: { energy: 0, nerve: 0 },
    levelUps: [],
  };

  for (let i = 1; i < records.length; i += 1) {
    const prev = records[i - 1];
    const next = records[i];
    // Un trou de plus d'une heure = coach eteint, on ne compte pas le gaspillage.
    const gapSeconds = (next.ts - prev.ts) / 1000;
    if (gapSeconds > 3600) continue;

    for (const key of ['energy', 'nerve']) {
      const wasted = wastedBetween(prev, next, key);
      out.wasted[key] += wasted;
      if (wasted > 0) out.fullSeconds[key] += gapSeconds;
    }

    if (prev.level !== null && next.level !== null && next.level > prev.level) {
      out.levelUps.push({ at: next.ts, from: prev.level, to: next.level });
    }
  }

  out.wasted.energy = Math.round(out.wasted.energy);
  out.wasted.nerve = Math.round(out.wasted.nerve);
  out.fullSeconds.energy = Math.round(out.fullSeconds.energy);
  out.fullSeconds.nerve = Math.round(out.fullSeconds.nerve);
  return out;
}

module.exports = { Tracker, summarize, toRecord, wastedBetween, DEFAULT_FILE };
