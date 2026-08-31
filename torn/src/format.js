'use strict';

const { formatSeconds } = require('./advisor');

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));

const style = {
  bold: c(1),
  dim: c(2),
  red: c(31),
  green: c(32),
  yellow: c(33),
  blue: c(34),
  magenta: c(35),
  cyan: c(36),
};

const BAR_WIDTH = 24;

function renderBar(bar) {
  if (!bar) return '';
  const filled = Math.round(Math.min(1, bar.ratio) * BAR_WIDTH);
  const color = bar.isFull ? style.red : bar.ratio >= 0.9 ? style.yellow : style.green;
  const track = color('█'.repeat(filled)) + style.dim('░'.repeat(BAR_WIDTH - filled));
  const label = `${bar.current}/${bar.maximum}`.padEnd(11);
  const eta = bar.isFull ? style.red('PLEINE — gaspillage') : style.dim(`pleine dans ${formatSeconds(bar.fullIn)}`);
  return `  ${bar.name.padEnd(7)} ${track} ${label} ${eta}`;
}

function renderSnapshot(snapshot, result) {
  const lines = [];
  const p = snapshot.player;
  const who = p.name ? `${p.name} [${p.id ?? '?'}]` : 'Joueur';
  lines.push(style.bold(`\n  ${who} — niveau ${p.level ?? '?'}   ${style.dim(new Date(snapshot.fetchedAt).toLocaleTimeString())}`));
  lines.push('');

  for (const name of ['energy', 'nerve', 'happy', 'life']) {
    const bar = snapshot.bars[name];
    if (bar) lines.push(renderBar(bar));
  }

  if (result.blockers.length) {
    lines.push('');
    for (const b of result.blockers) {
      lines.push(`  ${style.red('■')} ${style.bold(b.title)} ${style.dim(`(${formatSeconds(b.seconds)})`)}`);
      if (b.detail) lines.push(`    ${style.dim(b.detail)}`);
    }
  }

  lines.push('');
  if (result.next) {
    lines.push(`  ${style.cyan('▶ A FAIRE')} ${style.bold(result.next.title)}`);
    if (result.next.detail) lines.push(`    ${style.dim(result.next.detail)}`);
  } else if (result.blockers.length) {
    lines.push(`  ${style.dim('Rien a depenser pour l’instant — attends la fin du blocage ci-dessus.')}`);
  } else {
    lines.push(`  ${style.green('✓')} Rien d’urgent : les barres se rechargent, reviens plus tard.`);
  }

  const rest = result.next ? result.advice.slice(1) : result.advice;
  if (rest.length) {
    lines.push('');
    lines.push(style.dim('  Ensuite :'));
    for (const a of rest) lines.push(`    ${style.dim('·')} ${a.title}`);
  }

  lines.push('');
  return lines.join('\n');
}

function renderReport(report) {
  if (report.samples === 0) {
    return '\n  Aucun historique. Lance `npm run torn:watch` pour commencer a mesurer.\n';
  }
  const span = formatSeconds((report.to - report.from) / 1000);
  const lines = [
    style.bold(`\n  Historique — ${report.samples} releves sur ${span}`),
    '',
    `  Energie gaspillee : ${style.yellow(report.wasted.energy)} (barre pleine pendant ${formatSeconds(report.fullSeconds.energy)})`,
    `  Nerve gaspillee   : ${style.yellow(report.wasted.nerve)} (barre pleine pendant ${formatSeconds(report.fullSeconds.nerve)})`,
  ];
  if (report.levelUps.length) {
    lines.push('', style.bold('  Niveaux gagnes :'));
    for (const l of report.levelUps) {
      lines.push(`    ${new Date(l.at).toLocaleString()} — ${l.from} → ${l.to}`);
    }
  }
  lines.push('');
  return lines.join('\n');
}

function money(n) {
  return `$${Math.round(n).toLocaleString('en-US')}`;
}

function renderMarket(scan) {
  const lines = [''];

  if (scan.unresolved.length) {
    lines.push(
      style.yellow(`  Objets introuvables dans le catalogue Torn : ${scan.unresolved.join(', ')}`),
      style.dim('  Corrige les noms dans torn/config/coach.json (orthographe exacte du jeu).'),
      ''
    );
  }

  for (const e of scan.errors) lines.push(style.red(`  ! ${e.name} : ${e.message}`));

  if (scan.opportunities.length === 0) {
    lines.push(style.dim(`  Aucune opportunite sur ${scan.scanned} objet(s) surveille(s).`), '');
    return lines.join('\n');
  }

  lines.push(style.bold(`  ${scan.opportunities.length} opportunite(s) — a verifier puis acheter a la main`), '');
  for (const o of scan.opportunities) {
    lines.push(
      `  ${style.bold(o.name)} ${style.dim(`(${o.source})`)}`,
      `    ${money(o.cost)} vs valeur marche ${money(o.marketValue)} — ${style.green(`-${o.discountPercent}%`)}`,
      `    ${o.affordable}/${o.quantity} unite(s) → marge estimee ${style.green(money(o.totalProfit))}`,
      style.dim(`    https://www.torn.com/imarket.php#/p=shop&step=shop&type=&searchname=${encodeURIComponent(o.name)}`),
      ''
    );
  }
  lines.push(
    style.dim('  Rappel : `market_value` est une moyenne glissante. Une forte remise peut'),
    style.dim('  signaler une bonne affaire comme un prix qui vient de chuter. Verifie avant.'),
    ''
  );
  return lines.join('\n');
}

function renderAttacks(analysis) {
  const { summary, advice } = analysis;
  const lines = [''];

  if (summary.total === 0) {
    lines.push(style.dim('  Aucune attaque dans le journal sur la periode demandee.'), '');
    return lines.join('\n');
  }

  const span = summary.from && summary.to ? formatSeconds((summary.to - summary.from) / 1000) : '?';
  lines.push(style.bold(`  ${summary.total} attaque(s) sur ${span}`), '');
  lines.push(
    `  Laissees sur place : ${style.green(summary.counts.leave)}   ${style.dim('(XP maximale)')}`,
    `  Volees             : ${summary.counts.mug > 0 ? style.yellow(summary.counts.mug) : summary.counts.mug}   ${style.dim('(XP reduite)')}`,
    `  Hospitalisees      : ${summary.counts.hosp > 0 ? style.yellow(summary.counts.hosp) : summary.counts.hosp}   ${style.dim('(XP reduite)')}`,
    `  Perdues            : ${summary.counts.loss > 0 ? style.red(summary.counts.loss) : summary.counts.loss}`
  );

  if (summary.leaveRatio !== null) {
    const pct = Math.round(summary.leaveRatio * 100);
    const color = pct >= 90 ? style.green : pct >= 60 ? style.yellow : style.red;
    lines.push('', `  Efficacite XP des victoires : ${color(pct + '%')} ${style.dim('conclues de facon optimale')}`);
  }
  if (summary.averageDefenderLevel !== null) {
    lines.push(
      `  Niveau moyen des cibles     : ${summary.averageDefenderLevel} ${style.dim(`(sur ${summary.defenderLevelsKnown} connue(s))`)}`
    );
  }
  lines.push(`  Respect gagne               : ${summary.respect}`);

  if (advice.length) {
    lines.push('');
    for (const a of advice) {
      lines.push(`  ${style.cyan('▶')} ${style.bold(a.title)}`);
      lines.push(`    ${style.dim(a.detail)}`);
    }
  }

  lines.push(
    '',
    style.dim('  L’XP est cachee par design dans Torn : aucun outil ne peut te donner le'),
    style.dim('  nombre exact d’attaques restantes. Ce qui precede mesure la *qualite* de'),
    style.dim('  tes attaques, ce qui est la seule variable que tu controles.'),
    ''
  );
  return lines.join('\n');
}

module.exports = { renderSnapshot, renderReport, renderMarket, renderAttacks, renderBar, style };
