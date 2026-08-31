# Torn Coach

Assistant de leveling pour [Torn](https://www.torn.com) — **en lecture seule**.

## Ce que fait cet outil (et ce qu'il ne fait pas)

Il **ne joue pas à ta place**. Automatiser les actions de jeu (attaques, crimes,
gym) via script ou pilotage de navigateur est interdit par les règles de Torn et
se solde par un bannissement. L'API Torn est d'ailleurs en lecture seule : aucun
endpoint ne permet de s'entraîner ou de commettre un crime.

Ce qu'il fait, c'est supprimer la principale perte de progression : la
régénération gaspillée. Sur Torn, l'XP vient des crimes (nerve) et des attaques
(énergie). Chaque minute passée avec une barre pleine est de la progression
perdue pour toujours. Le coach surveille tes barres, t'alerte au bon moment, et
te dit quoi faire en priorité.

## Installation

```bash
npm install
cp torn/.env.example .env      # puis renseigne TORN_API_KEY
```

La clé se génère dans Torn : **Settings → API Key**. Une clé **Limited Access**
suffit — n'utilise pas une clé Full Access pour cet outil, elle donne bien plus
d'accès que nécessaire. Le fichier `.env` est ignoré par git ; la clé n'est
jamais écrite dans les logs ni dans les messages d'erreur.

## Utilisation

```bash
npm run torn                   # état actuel + action recommandée
npm run torn:watch             # surveillance continue avec alertes
npm run torn:report            # combien de régen tu as gaspillé cette semaine
npm run torn:dashboard         # tableau de bord sur http://127.0.0.1:3100
```

`watch` interroge l'API toutes les 60 s (`--every N` pour changer, minimum 30 s)
et envoie une alerte dès qu'une barre se remplit — notification de bureau, bip
terminal, et webhook Discord si `TORN_DISCORD_WEBHOOK` est renseigné. L'alerte
ne se répète pas tant que la barre reste pleine, et se réarme quand elle
redescend.

## Priorités des conseils

| Priorité | Situation | Pourquoi |
|---|---|---|
| 105 | Chaîne de faction active | Meilleur rendement XP, et elle expire vite |
| 100 | Énergie ou nerve pleine | Régénération perdue en ce moment même |
| 90 | Barre pleine dans moins de 15 min | Fenêtre pour planifier la dépense |
| 70 | Refill quotidien non utilisé | Une barre entière gratuite, une fois par jour |
| 60 | Barre au-dessus de 90 % | Bonne fenêtre de session |
| 40 | Happy au plancher, énergie à dépenser | À happy bas, la même énergie rapporte moins de stats |
| 30 | Aucun cours d'éducation en cours | Tourne en arrière-plan, ne coûte aucune énergie |

Un vol en cours, l'hôpital ou la prison désactivent la recommandation d'action :
les conseils restent affichés, mais rien n'est dépensable.

## Réglages

`torn/config/coach.json` — seuils d'alerte, fréquence, barres à surveiller,
valeurs des consommables. Rien n'est figé dans le code.

## Historique

`watch` et `status` écrivent un relevé dans `torn/data/history.jsonl` (ignoré par
git). `torn:report` en tire tes chiffres réels : énergie et nerve gaspillées,
temps passé barre pleine, niveaux gagnés. C'est mesuré sur tes données, pas
estimé par une formule.

## Tests

```bash
npm test
```

Tout est testé hors réseau : le client API est injectable, l'horloge et les
appels HTTP sont simulés.
