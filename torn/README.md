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

## Scanner de l'Item Market

```bash
npm run torn:market            # un passage sur la watchlist
npm run torn:market -- --watch # scan toutes les 5 min avec alertes
```

Le scanner lit les annonces publiques via l'API, les compare à la valeur de
marché de l'objet, et signale celles qui passent tes seuils — avec le lien
direct vers l'objet sur le market. **Il n'achète rien.** L'API Torn n'expose
aucun endpoint d'achat, et automatiser le clic en pilotant le site est un motif
de bannissement. Le script trouve l'affaire, tu cliques.

La watchlist se définit **par nom** dans `torn/config/coach.json` ; les noms sont
résolus contre le catalogue Torn au lancement, donc aucun ID d'objet n'est codé
en dur, et un nom mal orthographié te le dit au lieu de disparaître en silence.

Deux limites à garder en tête :

- `market_value` est une **moyenne glissante**. Une annonce 30 % en dessous peut
  être une bonne affaire — ou un prix de marché qui vient de s'effondrer, auquel
  cas la « marge » est fictive. Le scanner signale, il ne juge pas.
- Entre l'alerte et ton clic il y a quelques secondes. Sur les objets très
  liquides, les meilleures annonces partent avant. C'est structurel, pas un
  défaut à corriger : la corriger reviendrait à automatiser l'achat.

## Combien de joueurs battre pour le niveau 15 ?

**Personne ne peut te donner le chiffre exact, et ce n'est pas une limite de cet
outil.** L'expérience est *cachée par design* dans Torn : aucune table d'XP par
niveau n'est publiée, et l'API n'expose aucun champ d'expérience. Le seul moyen
de voir ta progression est la Fortune Teller, en Chine — donc inaccessible avant
le niveau 15, puisque le voyage se débloque précisément à ce niveau.

Ce qu'on sait, en revanche :

- **Repère communautaire : ~125 attaques** sur des cibles de leveling correctes.
  C'est un ordre de grandeur, pas une garantie.
- **L'XP d'une attaque dépend du NIVEAU de la cible, pas de ses stats.** D'où la
  stratégie : viser des joueurs de *haut niveau mais faibles en combat*
  (« leveling targets »).
- **L'issue change tout : laisser sur place > voler > hospitaliser.** Laisser
  donne l'XP maximale ; voler tombe autour de 55-60 %. Hospitaliser une cible
  partagée la bloque en plus pour les autres joueurs.
- Les crimes, la gym, le travail et certains company specials donnent aussi de
  l'XP — l'attaque n'est pas la seule source.
- Ordres de grandeur observés : 1 à 3 jours avec de l'aide financière, une
  dizaine de jours en jouant sérieusement, plus longtemps en énergie naturelle.

### `attacks` — mesurer ce que tu contrôles

```bash
npm run torn:attacks                    # 7 derniers jours
npm run torn:attacks -- --since 30      # 30 jours
npm run torn:attacks -- --enrich        # + niveau réel des cibles (1 appel API par joueur)
```

Puisque l'XP est cachée, la commande ne prétend pas compter tes XP. Elle mesure
la **qualité** de tes attaques, qui est la vraie variable d'optimisation :

- combien de victoires laissées sur place vs volées/hospitalisées (efficacité XP) ;
- le niveau moyen de tes cibles, pour vérifier que tu vises assez haut ;
- ta position vis-à-vis du repère des ~125 attaques.

`--enrich` va chercher le niveau des défenseurs profil par profil, plafonné par
`maxEnrichLookups` pour ne pas transformer une analyse en centaines de requêtes.

## Trouver des cibles (niveau élevé, stats faibles)

**Les battle stats d'autrui sont des données privées.** Aucune clé API, quel que
soit son niveau d'accès, ne les expose — c'est une garantie du jeu, pas une
limite de cet outil. Il n'existe donc aucun moyen de demander « les comptes
niveau 20+ sous 400 stats ».

Ce qui est mesurable, c'est le **Fair Fight** renvoyé après chaque attaque : il
dépend du rapport de force, donc il se renverse.

```
BSS            = somme des racines carrées des 4 stats, arrondie
DefenderScore  = (FF − 1) × 3/8 × AttackerScore
DefenderStats ≈ DefenderScore² / 4        (si la cible est équilibrée)
```

```bash
npm run torn:targets                              # seuils par défaut : niveau ≥ 20, stats ≤ 400
npm run torn:targets -- --min-level 30 --max-stats 250
npm run torn:targets -- --ids 1234567,2345678     # évaluer des IDs d'une liste communautaire
```

Trois limites, toutes appliquées dans le code plutôt que passées sous silence :

- **Le Fair Fight n'existe que pour les joueurs que tu as déjà attaqués.** Cet
  outil lit ton historique, il n'explore pas la base joueurs. Sans historique, il
  ne renvoie rien — et le dit.
- **L'estimation suppose une cible équilibrée.** Une cible déséquilibrée a *plus*
  de stats totales pour le même score : traite le chiffre comme un plancher.
- **FF plafonne par le bas à 1.** À FF = 1 la cible est simplement « beaucoup
  plus faible que toi » : affiché comme *sous le seuil de mesure*, pas comme 0.

Pour découvrir des cibles que tu n'as jamais attaquées, utilise les pools
communautaires — [FFScouter Target Finder](https://ffscouter.com/guides/target-finder)
filtre exactement sur niveau / estimation de stats / dernière activité, à partir
d'estimations FF mutualisées — puis passe les IDs à `--ids` pour les vérifier
avec ton propre historique.

Ce que cet outil ne fait **pas** : énumérer la base joueurs en itérant sur les
identifiants. À 60 requêtes/minute cela représente des années de requêtes pour
des millions de comptes, et c'est un usage abusif de l'API.

Deux remarques pratiques : une cible **sans faction et inactive depuis
longtemps** ne ripostera pas, contrairement à un membre actif d'une faction
organisée ; et un **rang bas pour un niveau élevé** est un bon signal, le rang
étant dérivé du niveau, des crimes, du networth et des stats.

## Aller vite au niveau 15, légalement

Les leviers réels, par ordre de rendement :

1. **Ne jamais laisser une barre pleine.** C'est le point n°1 et c'est
   précisément ce que `watch` surveille. Sur une semaine, quelques heures de
   nerve saturée coûtent plus que n'importe quelle optimisation fine.
2. **Nerve → crimes en continu.** Aux premiers niveaux c'est la source d'XP la
   plus régulière et la moins risquée.
3. **Les deux refills quotidiens.** Une barre entière d'énergie et une de nerve
   par jour, remise à zéro chaque jour : non utilisées, elles sont perdues.
4. **Xanax pour la sortie d'énergie**, dans la limite de ton cooldown drogue —
   le coach affiche le cooldown réel, ne travaille pas de mémoire.
5. **Les chaînes de faction.** Meilleur rendement XP du jeu, mais elles expirent
   vite : le coach les met en priorité absolue tant qu'elles tiennent.
6. **L'éducation**, en arrière-plan. Aucune énergie consommée, donc aucun
   arbitrage à faire — un cours doit toujours tourner.

Et l'erreur la plus coûteuse, parce qu'elle est invisible : **gagner un combat
puis le conclure en vol ou en hospitalisation**. L'énergie est dépensée en
entier, l'XP arrive amputée. C'est exactement ce que `attacks` détecte.

### Sources

- [Level and Ranks — wiki officiel](https://wiki.torn.com/wiki/Level_and_Ranks)
- [FAQ — wiki officiel](https://wiki.torn.com/wiki/FAQ) (l'XP est cachée)
- [Getting to Level 15 — FFScouter](https://ffscouter.com/guides/level-15)
- [Leveling Guide — TornW3B](https://www.weav3r.dev/guides/leveling)
- [GET TO LEVEL 15 as fast as possible — TornStats](https://www.tornstats.com/guides/show/35)
- [Level 15 Guide — TC Essentials](https://tc-essentials.oran.pw/docs/prologue/level15/)
- [Fair Fight Explained — FFScouter](https://ffscouter.com/guides/fair-fight-explained)
- [Estimating opponent's stats from attacks — forums Torn](https://www.torn.com/forums.php?p=threads&f=61&t=16209964)
- [Rank — wiki officiel](https://wiki.torn.com/wiki/Rank)
- [API key levels and safety — FFScouter](https://ffscouter.com/guides/api-keys) (les battle stats d'autrui sont privées)

Pour les chiffres (régen par tick, cooldowns, temps avant saturation), lis-les
dans l'app : ils viennent de l'API et sont propres à ton compte.

## Ce que cet outil ne fera jamais

- commettre des crimes, attaquer ou s'entraîner à ta place ;
- acheter automatiquement sur le market ;
- exploiter un bug du jeu.

Ces trois choses sont interdites par les règles de Torn et sanctionnées par un
bannissement, généralement définitif. Un compte banni ne monte plus de niveau.

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
