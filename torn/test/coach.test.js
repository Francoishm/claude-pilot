'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { Coach, readConfig } = require('../src/coach');
const { createApp } = require('../src/dashboard');
const { Notifier } = require('../src/notify');

const FULL_ENERGY = {
  name: 'Tester',
  player_id: 7,
  level: 15,
  status: { state: 'Okay', until: 0 },
  energy: { current: 150, maximum: 150, increment: 5, interval: 600, ticktime: 0, fulltime: 0 },
  nerve: { current: 3, maximum: 22, increment: 1, interval: 300, ticktime: 100, fulltime: 5700 },
  happy: { current: 3000, maximum: 4000, increment: 5, interval: 900, ticktime: 100, fulltime: 90000 },
  cooldowns: { drug: 500, medical: 0, booster: 0 },
  refills: { energy_refill_used: true, nerve_refill_used: true },
  education: { education_current: 12, education_timeleft: 5000 },
  travel: { time_left: 0 },
};

/** Faux client API : compte les appels, sert un payload fixe. */
function fakeApi(payload = FULL_ENERGY) {
  let calls = 0;
  return {
    get calls() {
      return calls;
    },
    async fetchPlayer() {
      calls += 1;
      return payload;
    },
  };
}

const noopTracker = { record() {}, report: () => ({ samples: 0 }) };

test('readConfig refuse une cle vide', () => {
  assert.throws(() => readConfig({ TORN_API_KEY: '   ' }), /TORN_API_KEY absente/);
});

test('readConfig lit les options facultatives', () => {
  const cfg = readConfig({ TORN_API_KEY: 'K', TORN_DASHBOARD_PORT: '4242', TORN_DISCORD_WEBHOOK: 'https://h' });
  assert.equal(cfg.key, 'K');
  assert.equal(cfg.dashboardPort, 4242);
  assert.equal(cfg.webhookUrl, 'https://h');
});

test('poll renvoie instantane et conseils', async () => {
  const coach = new Coach({ key: 'K' }, { api: fakeApi(), tracker: noopTracker, notifier: new Notifier({ desktop: false }) });
  const { snapshot, result } = await coach.poll();
  assert.equal(snapshot.player.name, 'Tester');
  assert.equal(result.next.id, 'energy-full');
});

test('alertOnFull alerte une seule fois tant que la barre reste pleine', async () => {
  const notifier = new Notifier({ desktop: false, cooldownMs: 60000 });
  const coach = new Coach({ key: 'K' }, { api: fakeApi(), tracker: noopTracker, notifier });
  const { snapshot } = await coach.poll();

  assert.deepEqual(await coach.alertOnFull(snapshot, ['energy', 'nerve']), ['energy']);
  assert.deepEqual(await coach.alertOnFull(snapshot, ['energy', 'nerve']), []);
});

test('alertOnFull rearme l’alerte quand la barre redescend', async () => {
  const notifier = new Notifier({ desktop: false, cooldownMs: 60000 });
  const coach = new Coach({ key: 'K' }, { api: fakeApi(), tracker: noopTracker, notifier });
  const { snapshot } = await coach.poll();
  await coach.alertOnFull(snapshot, ['energy']);

  const drained = { ...snapshot, bars: { ...snapshot.bars, energy: { ...snapshot.bars.energy, current: 10, isFull: false } } };
  await coach.alertOnFull(drained, ['energy']);

  assert.deepEqual(await coach.alertOnFull(snapshot, ['energy']), ['energy']);
});

test('le dashboard sert /api/status et met en cache les appels', async () => {
  const api = fakeApi();
  const coach = new Coach({ key: 'K' }, { api, tracker: noopTracker, notifier: new Notifier({ desktop: false }) });
  const server = createApp(coach).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    const [a, b] = await Promise.all([
      fetch(`${base}/api/status`).then((r) => r.json()),
      fetch(`${base}/api/status`).then((r) => r.json()),
    ]);
    assert.equal(a.next.id, 'energy-full');
    assert.equal(b.next.id, 'energy-full');
    assert.equal((await fetch(`${base}/api/status`).then((r) => r.json())).snapshot.player.level, 15);
    assert.equal(api.calls, 1, 'les requetes concurrentes et rapprochees partagent un seul appel API');
  } finally {
    server.close();
  }
});

test('le dashboard renvoie 502 quand l’API Torn echoue', async () => {
  const brokenApi = {
    async fetchPlayer() {
      throw new Error('Torn a refuse la requete');
    },
  };
  const coach = new Coach({ key: 'K' }, { api: brokenApi, tracker: noopTracker, notifier: new Notifier({ desktop: false }) });
  const server = createApp(coach).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));

  try {
    const res = await fetch(`http://127.0.0.1:${server.address().port}/api/status`);
    assert.equal(res.status, 502);
    assert.match((await res.json()).error, /Torn a refuse/);
  } finally {
    server.close();
  }
});

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadEnv } = require('../src/coach');
const { isPubliclyBound } = require('../src/dashboard');

test('readConfig ecoute sur localhost par defaut', () => {
  assert.equal(readConfig({ TORN_API_KEY: 'K' }).dashboardHost, '127.0.0.1');
  assert.equal(readConfig({ TORN_API_KEY: 'K', TORN_DASHBOARD_HOST: '0.0.0.0' }).dashboardHost, '0.0.0.0');
});

test('isPubliclyBound distingue une ecoute locale d’une ecoute reseau', () => {
  for (const local of ['127.0.0.1', 'localhost', '::1']) assert.equal(isPubliclyBound(local), false);
  for (const open of ['0.0.0.0', '192.168.1.10', '::']) assert.equal(isPubliclyBound(open), true);
});

test('loadEnv prefere le .env du sous-projet a celui de la racine', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'torn-env-'));
  const local = path.join(dir, 'local.env');
  const root = path.join(dir, 'root.env');
  fs.writeFileSync(local, 'TORN_TEST_MARKER=local\n');
  fs.writeFileSync(root, 'TORN_TEST_MARKER=root\n');

  assert.equal(loadEnv([local, root]), local);
  assert.equal(process.env.TORN_TEST_MARKER, 'local');

  delete process.env.TORN_TEST_MARKER;
  assert.equal(loadEnv([path.join(dir, 'absent.env'), root]), root, 'repli sur la racine');
  assert.equal(process.env.TORN_TEST_MARKER, 'root');

  delete process.env.TORN_TEST_MARKER;
  fs.rmSync(dir, { recursive: true, force: true });
});

test('loadEnv ne plante pas quand aucun .env n’existe', () => {
  assert.equal(loadEnv(['/nexiste/pas/.env']), null);
});
