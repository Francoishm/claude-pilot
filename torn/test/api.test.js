'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { TornApi, TornApiError, RateLimiter } = require('../src/api');

function jsonResponse(body, status = 200) {
  return { status, json: async () => body };
}

/** Fabrique un faux fetch qui enregistre les appels recus. */
function mockFetch(responses) {
  const calls = [];
  const queue = [...responses];
  const fn = async (url, opts) => {
    calls.push({ url: new URL(url), opts });
    const next = queue.shift();
    if (typeof next === 'function') return next();
    return next;
  };
  fn.calls = calls;
  return fn;
}

test('la cle part en en-tete Authorization, jamais dans l’URL', async () => {
  const fetchImpl = mockFetch([jsonResponse({ level: 3 })]);
  const api = new TornApi({ key: 'SECRET', fetchImpl });
  await api.get('user', ['basic']);

  const { url, opts } = fetchImpl.calls[0];
  assert.equal(opts.headers.Authorization, 'ApiKey SECRET');
  assert.equal(url.searchParams.get('key'), null);
  assert.equal(url.searchParams.get('selections'), 'basic');
});

test('bascule sur le parametre de requete si l’en-tete est refuse', async () => {
  const fetchImpl = mockFetch([
    jsonResponse({ error: { code: 2, error: 'Incorrect key' } }),
    jsonResponse({ level: 3 }),
  ]);
  const api = new TornApi({ key: 'SECRET', fetchImpl });
  const body = await api.get('user', ['basic']);

  assert.deepEqual(body, { level: 3 });
  assert.equal(fetchImpl.calls.length, 2);
  assert.equal(fetchImpl.calls[1].url.searchParams.get('key'), 'SECRET');
  assert.equal(fetchImpl.calls[1].opts.headers.Authorization, undefined);
});

test('une erreur Torn non recuperable remonte telle quelle', async () => {
  const fetchImpl = mockFetch([jsonResponse({ error: { code: 16, error: 'Access level insufficient' } })]);
  const api = new TornApi({ key: 'SECRET', fetchImpl, maxRetries: 0 });
  await assert.rejects(() => api.get('user', ['basic']), (err) => {
    assert.ok(err instanceof TornApiError);
    assert.equal(err.code, 16);
    assert.equal(err.retryable, false);
    // Le message d'erreur ne doit jamais contenir la cle.
    assert.ok(!err.message.includes('SECRET'));
    return true;
  });
});

test('un rate limit est reessaye puis reussit', async () => {
  const fetchImpl = mockFetch([jsonResponse({}, 429), jsonResponse({ level: 3 })]);
  const api = new TornApi({ key: 'SECRET', fetchImpl, maxRetries: 1 });
  api.limiter = new RateLimiter(100000); // pas d'attente dans les tests
  const originalSetTimeout = global.setTimeout;
  global.setTimeout = (fn) => originalSetTimeout(fn, 0);
  try {
    assert.deepEqual(await api.get('user'), { level: 3 });
  } finally {
    global.setTimeout = originalSetTimeout;
  }
  assert.equal(fetchImpl.calls.length, 2);
});

test('une cle absente est refusee a la construction', () => {
  assert.throws(() => new TornApi({ key: '' }), /Cle API manquante/);
});

test('fetchPlayer demande toutes les selections utiles en un appel', async () => {
  const fetchImpl = mockFetch([jsonResponse({ level: 3 })]);
  const api = new TornApi({ key: 'SECRET', fetchImpl });
  await api.fetchPlayer();

  const selections = fetchImpl.calls[0].url.searchParams.get('selections').split(',');
  for (const wanted of ['basic', 'bars', 'cooldowns', 'travel', 'refills', 'education']) {
    assert.ok(selections.includes(wanted), `selection manquante : ${wanted}`);
  }
  assert.equal(fetchImpl.calls.length, 1);
});

test('le limiteur espace les requetes', async () => {
  const limiter = new RateLimiter(60); // 1 par seconde
  const t0 = Date.now();
  await limiter.wait();
  const first = Date.now() - t0;
  assert.ok(first < 50, 'la premiere requete ne doit pas attendre');
  assert.ok(limiter.nextSlot > Date.now(), 'le creneau suivant est repousse');
});
