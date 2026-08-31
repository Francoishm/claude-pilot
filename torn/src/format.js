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

module.exports = { renderSnapshot, renderReport, renderBar, style };
