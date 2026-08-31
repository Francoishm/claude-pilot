'use strict';

/**
 * Client HTTP pour l'API Torn.
 *
 * Lecture seule : ce module n'appelle que des endpoints `user` / `torn`.
 * La cle n'est jamais loguee ni incluse dans les messages d'erreur.
 */

const DEFAULT_BASE = 'https://api.torn.com';

// Torn autorise 100 requetes / minute par cle. On reste tres en dessous.
const RATE_LIMIT_PER_MINUTE = 60;

// Codes d'erreur Torn qui valent la peine d'etre reessayes.
const RETRYABLE_CODES = new Set([5, 17]);

class TornApiError extends Error {
  constructor(message, { code = null, retryable = false } = {}) {
    super(message);
    this.name = 'TornApiError';
    this.code = code;
    this.retryable = retryable;
  }
}

class RateLimiter {
  constructor(perMinute = RATE_LIMIT_PER_MINUTE) {
    this.minIntervalMs = Math.ceil(60000 / perMinute);
    this.nextSlot = 0;
  }

  async wait() {
    const now = Date.now();
    const slot = Math.max(now, this.nextSlot);
    this.nextSlot = slot + this.minIntervalMs;
    if (slot > now) await sleep(slot - now);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class TornApi {
  /**
   * @param {object} opts
   * @param {string} opts.key       Cle API Torn.
   * @param {string} [opts.base]    Base URL de l'API.
   * @param {number} [opts.timeoutMs]
   * @param {number} [opts.maxRetries]
   * @param {typeof fetch} [opts.fetchImpl] Injectable pour les tests.
   */
  constructor({ key, base = DEFAULT_BASE, timeoutMs = 15000, maxRetries = 3, fetchImpl = globalThis.fetch } = {}) {
    if (!key) throw new TornApiError('Cle API manquante : renseigne TORN_API_KEY dans .env');
    this.key = key;
    this.base = base.replace(/\/+$/, '');
    this.timeoutMs = timeoutMs;
    this.maxRetries = maxRetries;
    this.fetch = fetchImpl;
    this.limiter = new RateLimiter();
    // Torn accepte la cle en en-tete (prefere : elle ne finit pas dans les logs
    // du proxy) mais pas sur toutes les routes. On bascule sur le parametre de
    // requete uniquement si l'en-tete est rejete.
    this.authMode = 'header';
  }

  /**
   * @param {string} section  ex. 'user'
   * @param {string[]} selections
   * @param {object} [params]  parametres additionnels (from, to, ...)
   */
  async get(section, selections = [], params = {}) {
    const query = { ...params };
    if (selections.length) query.selections = selections.join(',');

    let lastError;
    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      try {
        return await this.#request(section, query);
      } catch (err) {
        lastError = err;
        if (!(err instanceof TornApiError) || !err.retryable || attempt === this.maxRetries) throw err;
        // Backoff exponentiel : 2s, 4s, 8s.
        await sleep(2000 * 2 ** attempt);
      }
    }
    throw lastError;
  }

  async #request(section, query) {
    await this.limiter.wait();

    const url = new URL(`${this.base}/${section}/`);
    for (const [k, v] of Object.entries(query)) url.searchParams.set(k, String(v));

    const headers = { Accept: 'application/json' };
    if (this.authMode === 'header') headers.Authorization = `ApiKey ${this.key}`;
    else url.searchParams.set('key', this.key);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let res;
    try {
      res = await this.fetch(url, { headers, signal: controller.signal });
    } catch (err) {
      if (err.name === 'AbortError') {
        throw new TornApiError(`Timeout apres ${this.timeoutMs}ms sur /${section}`, { retryable: true });
      }
      throw new TornApiError(`Erreur reseau sur /${section} : ${err.message}`, { retryable: true });
    } finally {
      clearTimeout(timer);
    }

    if (res.status === 429) throw new TornApiError('Rate limit Torn atteint', { code: 5, retryable: true });
    if (res.status >= 500) throw new TornApiError(`Torn a repondu ${res.status}`, { retryable: true });

    let body;
    try {
      body = await res.json();
    } catch {
      throw new TornApiError(`Reponse illisible de /${section} (HTTP ${res.status})`, { retryable: res.status >= 500 });
    }

    if (body && body.error) {
      const { code, error } = body.error;
      // L'en-tete Authorization n'est pas supporte partout : on retente une
      // seule fois en passant la cle en parametre de requete.
      if (this.authMode === 'header' && (code === 1 || code === 2)) {
        this.authMode = 'query';
        return this.#request(section, query);
      }
      throw new TornApiError(`Torn a refuse la requete : ${error} (code ${code})`, {
        code,
        retryable: RETRYABLE_CODES.has(code),
      });
    }

    return body;
  }

  /** Recupere tout ce dont le coach a besoin en un seul appel. */
  async fetchPlayer() {
    return this.get('user', [
      'basic',
      'bars',
      'cooldowns',
      'travel',
      'refills',
      'education',
      'money',
      'icons',
    ]);
  }
}

module.exports = { TornApi, TornApiError, RateLimiter, sleep, DEFAULT_BASE };
