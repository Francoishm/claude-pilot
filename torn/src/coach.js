'use strict';

/** Assemblage : config d'environnement + API + instantane + conseils. */

const path = require('path');
const { TornApi } = require('./api');
const { buildSnapshot } = require('./snapshot');
const { advise } = require('./advisor');
const { Tracker } = require('./tracker');
const { Notifier } = require('./notify');

function loadEnv() {
  require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });
}

/** Lit la configuration depuis l'environnement, sans jamais logger la cle. */
function readConfig(env = process.env) {
  const key = (env.TORN_API_KEY || '').trim();
  if (!key) {
    throw new Error(
      'TORN_API_KEY absente. Copie torn/.env.example vers .env a la racine et renseigne ta cle.'
    );
  }
  return {
    key,
    base: env.TORN_API_BASE || undefined,
    webhookUrl: env.TORN_DISCORD_WEBHOOK || null,
    dashboardPort: Number(env.TORN_DASHBOARD_PORT || 3100),
  };
}

class Coach {
  constructor(config, { api, tracker, notifier } = {}) {
    this.config = config;
    this.api = api ?? new TornApi({ key: config.key, base: config.base });
    this.tracker = tracker ?? new Tracker();
    this.notifier = notifier ?? new Notifier({ webhookUrl: config.webhookUrl });
  }

  /** Un cycle complet : appel API, normalisation, conseils. */
  async poll({ record = false } = {}) {
    const raw = await this.api.fetchPlayer();
    const snapshot = buildSnapshot(raw);
    const result = advise(snapshot);
    if (record) this.tracker.record(snapshot);
    return { snapshot, result };
  }

  /** Alerte une fois par barre qui vient de se remplir. */
  async alertOnFull(snapshot, barNames) {
    const sent = [];
    for (const name of barNames) {
      const bar = snapshot.bars?.[name];
      if (!bar || !bar.isFull) {
        // Barre redescendue : on reautorise l'alerte suivante.
        this.notifier.lastSent.delete(`full:${name}`);
        continue;
      }
      const ok = await this.notifier.send(
        `full:${name}`,
        `Torn — ${name} pleine`,
        `${bar.current}/${bar.maximum}, la regen part dans le vide.`
      );
      if (ok) sent.push(name);
    }
    return sent;
  }
}

module.exports = { Coach, readConfig, loadEnv };
