#!/usr/bin/env node
'use strict';

/**
 * Petit tableau de bord web (localhost par defaut).
 *
 * Il n'ecoute que sur 127.0.0.1 : la page expose des donnees de compte, elle
 * n'a rien a faire sur une interface publique sans authentification.
 */

const express = require('express');
const path = require('path');
const { Coach, readConfig, loadEnv } = require('./coach');

// Cache court : le dashboard peut etre ouvert dans plusieurs onglets sans
// multiplier les appels a l'API Torn.
const CACHE_MS = 20000;

function createApp(coach) {
  const app = express();
  app.use(express.static(path.join(__dirname, '..', 'public')));

  let cache = { at: 0, payload: null };
  let inFlight = null;

  app.get('/api/status', async (req, res) => {
    try {
      const now = Date.now();
      if (cache.payload && now - cache.at < CACHE_MS) return res.json(cache.payload);
      if (!inFlight) {
        inFlight = coach
          .poll({ record: true })
          .then(({ snapshot, result }) => {
            cache = { at: Date.now(), payload: { snapshot, ...result } };
            return cache.payload;
          })
          .finally(() => {
            inFlight = null;
          });
      }
      res.json(await inFlight);
    } catch (err) {
      res.status(502).json({ error: err.message });
    }
  });

  app.get('/api/report', (req, res) => {
    const days = Number(req.query.days || 7);
    res.json(coach.tracker.report(Date.now() - days * 24 * 3600 * 1000));
  });

  return app;
}

function start() {
  loadEnv();
  const config = readConfig();
  const coach = new Coach(config);
  const app = createApp(coach);
  app.listen(config.dashboardPort, '127.0.0.1', () => {
    process.stdout.write(`\n  Dashboard Torn : http://127.0.0.1:${config.dashboardPort}\n\n`);
  });
}

if (require.main === module) {
  try {
    start();
  } catch (err) {
    process.stderr.write(`\n  ${err.message}\n\n`);
    process.exit(1);
  }
}

module.exports = { createApp, CACHE_MS };
