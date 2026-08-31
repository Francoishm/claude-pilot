'use strict';

/**
 * Alertes. Le but est simple : etre prevenu au moment ou une barre se remplit,
 * pour ne pas laisser tourner la regen dans le vide.
 *
 * Deux canaux, tous deux optionnels :
 *  - webhook Discord (TORN_DISCORD_WEBHOOK)
 *  - notification de bureau via notify-send (Linux), sinon bip terminal
 */

const { execFile } = require('child_process');

class Notifier {
  /**
   * @param {object} opts
   * @param {string} [opts.webhookUrl]
   * @param {boolean} [opts.desktop]
   * @param {number} [opts.cooldownMs] anti-spam par cle d'alerte
   */
  constructor({ webhookUrl = null, desktop = true, cooldownMs = 10 * 60 * 1000, fetchImpl = globalThis.fetch } = {}) {
    this.webhookUrl = webhookUrl;
    this.desktop = desktop;
    this.cooldownMs = cooldownMs;
    this.fetch = fetchImpl;
    this.lastSent = new Map();
  }

  /** @returns {boolean} true si l'alerte a ete envoyee (false = etouffee). */
  async send(key, title, body = '', now = Date.now()) {
    const last = this.lastSent.get(key);
    if (last !== undefined && now - last < this.cooldownMs) return false;
    this.lastSent.set(key, now);

    await Promise.allSettled([this.#discord(title, body), this.#desktop(title, body)]);
    return true;
  }

  async #discord(title, body) {
    if (!this.webhookUrl) return;
    try {
      await this.fetch(this.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: `**${title}**${body ? `\n${body}` : ''}` }),
      });
    } catch {
      // Une alerte ratee ne doit jamais interrompre la surveillance.
    }
  }

  async #desktop(title, body) {
    if (!this.desktop) return;
    if (process.platform === 'linux') {
      await new Promise((resolve) => execFile('notify-send', [title, body], () => resolve()));
    }
    process.stdout.write('\x07'); // bip terminal, marche partout
  }
}

module.exports = { Notifier };
