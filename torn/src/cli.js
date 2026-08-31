#!/usr/bin/env node
'use strict';

const { Coach, readConfig, loadEnv } = require('./coach');
const { renderSnapshot, renderReport, renderMarket, renderAttacks, style } = require('./format');
const { MarketScanner } = require('./market');
const { AttackAnalyzer } = require('./attacks');
const { advise, DEFAULT_CONFIG } = require('./advisor');
const { Tracker } = require('./tracker');

const USAGE = `
  torn-coach — assistant de leveling Torn (lecture seule)

    status            Etat actuel des barres + action recommandee
    watch [--every N] Surveillance continue, alerte quand une barre est pleine
    market [--watch]  Scanne l'item market et signale les annonces sous-cotees
    attacks [--since D] [--enrich]
                      Analyse tes attaques : issues, niveau des cibles, efficacite XP
    report [--since D] Statistiques de gaspillage (D = nombre de jours, defaut 7)
    help              Cette aide

  La cle API se lit dans .env (TORN_API_KEY). Elle n'est jamais affichee.
`;

async function main(argv = process.argv.slice(2)) {
  const [command = 'status', ...rest] = argv;

  if (command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(USAGE);
    return 0;
  }

  if (command === 'report') {
    const days = Number(flag(rest, '--since') ?? 7);
    const since = Date.now() - days * 24 * 3600 * 1000;
    process.stdout.write(renderReport(new Tracker().report(since)));
    return 0;
  }

  loadEnv();
  const config = readConfig();
  const coach = new Coach(config);

  if (command === 'status') {
    const { snapshot, result } = await coach.poll({ record: true });
    process.stdout.write(renderSnapshot(snapshot, result));
    return 0;
  }

  if (command === 'attacks') {
    const days = Number(flag(rest, '--since') ?? 7);
    const analyzer = new AttackAnalyzer(coach.api);
    const analysis = await analyzer.analyze({
      sinceMs: Date.now() - days * 24 * 3600 * 1000,
      enrich: rest.includes('--enrich'),
    });
    process.stdout.write(renderAttacks(analysis));
    return 0;
  }

  if (command === 'market') {
    const scanner = new MarketScanner(coach.api);
    if (!rest.includes('--watch')) {
      process.stdout.write(renderMarket(await scanner.scan()));
      return 0;
    }
    return watchMarket(coach, scanner, Number(flag(rest, '--every') ?? 300));
  }

  if (command === 'watch') {
    const every = Number(flag(rest, '--every') ?? DEFAULT_CONFIG.pollSeconds);
    return watch(coach, every);
  }

  process.stderr.write(`Commande inconnue : ${command}\n${USAGE}`);
  return 1;
}

async function watch(coach, everySeconds) {
  const interval = Math.max(30, everySeconds) * 1000;
  process.stdout.write(
    style.dim(`\n  Surveillance active (toutes les ${interval / 1000}s). Ctrl+C pour arreter.\n`)
  );

  let stopped = false;
  process.on('SIGINT', () => {
    stopped = true;
    process.stdout.write(style.dim('\n  Arret.\n'));
    process.exit(0);
  });

  while (!stopped) {
    try {
      const { snapshot, result } = await coach.poll({ record: true });
      process.stdout.write(renderSnapshot(snapshot, result));
      const sent = await coach.alertOnFull(snapshot, DEFAULT_CONFIG.notifyOnFull);
      if (sent.length) process.stdout.write(style.yellow(`  → alerte envoyee : ${sent.join(', ')}\n`));
    } catch (err) {
      // Une panne reseau ne doit pas tuer une surveillance de plusieurs heures.
      process.stderr.write(style.red(`  ! ${err.message}\n`));
    }
    await new Promise((r) => setTimeout(r, interval));
  }
  return 0;
}

/**
 * Scan periodique du market. Par defaut 5 min : le catalogue bouge lentement et
 * un scan trop frequent consomme le quota API sans rien apporter.
 */
async function watchMarket(coach, scanner, everySeconds) {
  const interval = Math.max(60, everySeconds) * 1000;
  process.stdout.write(
    style.dim(`\n  Scan du market toutes les ${interval / 1000}s. Ctrl+C pour arreter.\n`)
  );
  process.on('SIGINT', () => {
    process.stdout.write(style.dim('\n  Arret.\n'));
    process.exit(0);
  });

  for (;;) {
    try {
      const scan = await scanner.scan();
      process.stdout.write(renderMarket(scan));
      for (const o of scan.opportunities) {
        await coach.notifier.send(
          `market:${o.itemId}`,
          `Torn — ${o.name} a -${o.discountPercent}%`,
          `${o.cost.toLocaleString('en-US')} vs ${o.marketValue.toLocaleString('en-US')} — achat manuel.`
        );
      }
    } catch (err) {
      process.stderr.write(style.red(`  ! ${err.message}\n`));
    }
    await new Promise((r) => setTimeout(r, interval));
  }
}

function flag(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      process.stderr.write(`\n  ${err.message}\n\n`);
      process.exit(1);
    }
  );
}

module.exports = { main };
