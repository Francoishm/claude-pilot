#!/usr/bin/env bash
#
# Installe le coach Torn comme service systemd.
# Idempotent : relancer le script met a jour le code et redemarre le service.
#
#   sudo ./install.sh
#
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="torn-coach"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
RUN_USER="${SUDO_USER:-$(id -un)}"

die() { printf '\n  ERREUR : %s\n\n' "$1" >&2; exit 1; }
say() { printf '  %s\n' "$1"; }

[[ $EUID -eq 0 ]] || die "a lancer avec sudo (installation d'une unite systemd)."
command -v systemctl >/dev/null 2>&1 || die "systemd introuvable sur cette machine."
command -v node >/dev/null 2>&1 || die "node introuvable. Installe Node.js 18 ou plus recent."

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[[ "$NODE_MAJOR" -ge 18 ]] || die "Node ${NODE_MAJOR} trop ancien : il faut 18 ou plus (fetch natif)."

# La cle API n'est jamais ecrite par ce script : elle doit deja etre en place.
[[ -f "${APP_DIR}/.env" ]] || die "${APP_DIR}/.env absent. Copie .env.example et renseigne TORN_API_KEY."
grep -qE '^TORN_API_KEY=.+' "${APP_DIR}/.env" || die "TORN_API_KEY vide dans ${APP_DIR}/.env."

say "Installation dans ${APP_DIR} (service lance par ${RUN_USER})"

# Le .env contient une cle API : lui seul doit pouvoir le lire.
chown "${RUN_USER}" "${APP_DIR}/.env"
chmod 600 "${APP_DIR}/.env"
say "Permissions du .env restreintes a ${RUN_USER} (600)."

say "Installation des dependances (production uniquement)..."
# torn/ ne depend que d'express et dotenv : aucune compilation native.
sudo -u "${RUN_USER}" npm ci --omit=dev --prefix "${APP_DIR}" >/dev/null 2>&1 \
  || sudo -u "${RUN_USER}" npm install --omit=dev --prefix "${APP_DIR}"

install -d -o "${RUN_USER}" -g "$(id -gn "${RUN_USER}")" "${APP_DIR}/data"

say "Verification (suite de tests)..."
sudo -u "${RUN_USER}" npm test --prefix "${APP_DIR}" >/dev/null 2>&1 \
  && say "Tests OK." || say "ATTENTION : les tests n'ont pas tous passe — installation poursuivie."

sed -e "s|@APP_DIR@|${APP_DIR}|g" -e "s|@RUN_USER@|${RUN_USER}|g" \
  "${APP_DIR}/deploy/torn-coach.service" > "${UNIT_PATH}"

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1
systemctl restart "${SERVICE_NAME}"
sleep 2

if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
  printf '\n  Le service n a pas demarre. Journal :\n\n'
  journalctl -u "${SERVICE_NAME}" -n 30 --no-pager
  exit 1
fi

PORT="$(grep -E '^TORN_DASHBOARD_PORT=' "${APP_DIR}/.env" | cut -d= -f2 | tr -d '[:space:]')"
PORT="${PORT:-3100}"

cat <<MSG

  Service actif : ${SERVICE_NAME}

  La page n ecoute que sur 127.0.0.1 et n a AUCUNE authentification.
  Pour y acceder depuis ton poste, ouvre un tunnel SSH :

      ssh -N -L ${PORT}:127.0.0.1:${PORT} ${RUN_USER}@<serveur>

  puis http://127.0.0.1:${PORT}/market.html

  Journal   : journalctl -u ${SERVICE_NAME} -f
  Redemarrer: sudo systemctl restart ${SERVICE_NAME}

MSG
