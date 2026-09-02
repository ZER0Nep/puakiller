# Déploiement du serveur d'enrichissement

Ce guide part d'une machine Linux vide et s'arrête à une usine planifiée qui tourne seule.
Compte environ vingt minutes, dont quinze à lire ce que la machine s'apprête à faire.

`README.md` explique pourquoi chaque protection existe. Ce fichier dit quoi taper.

Une chose avant de commencer. Cette machine ne va jamais sur le réseau du SOC, et le SOC ne lui
envoie jamais rien. Pas d'échantillon, pas de hash observé localement, pas de hostname, pas de
ticket. Si le serveur que tu prévois est dans le même VLAN que tes sondes, arrête-toi ici et
prends une autre machine.

---

## Ce qu'il te faut

Une VM Debian 12 ou Ubuntu 22.04, 1 vCPU, 1 Go de RAM, 10 Go de disque. Le conteneur est
plafonné à 512 Mo et 1 CPU, donc une petite instance suffit largement.

Docker Engine avec le plugin Compose v2. Vérifie que tu as bien la v2, la syntaxe `docker
compose` sans tiret :

```bash
docker compose version
```

Si la commande n'existe pas, installe le plugin avant d'aller plus loin. `docker-compose` v1 ne
lit pas les profils utilisés ici.

Git, et rien d'autre. Pas de Python sur l'hôte, pas de dépendance à installer. Tout tourne dans
l'image.

---

## Installation

```bash
git clone https://github.com/ZER0Nep/puakiller.git
cd puakiller/deploy
cp .env.example .env
chmod 600 .env
mkdir -p data/out data/state data/logs data/backups
```

Le conteneur tourne sous l'uid 10001 et le système de fichiers de l'image est en lecture seule.
Il écrit uniquement dans `deploy/data`, monté depuis l'hôte, donc ce répertoire doit lui
appartenir :

```bash
sudo chown -R 10001:10001 data
```

Oublier cette ligne est la première erreur que tu rencontreras. Elle se manifeste par un
`Permission denied` sur `/data/state/run.lock` au premier cycle.

Construis l'image :

```bash
docker compose build
```

Laisse `.env` avec toutes ses valeurs vides pour l'instant. L'étape suivante n'a besoin d'aucune
clé.

---

## Étape 1. Le mode hors ligne

Commence par vérifier ce que le conteneur peut joindre. La réponse doit être rien.

```bash
docker compose run --rm intel policy --mode fixture
```

Attendu :

```
mode=fixture outbound=none
  this mode makes no outbound connections at all
  triage: disabled (the pipeline is specified to work entirely without it)
```

Le service porte aussi `network_mode: none`, donc Docker lui retire sa pile réseau. Le programme
dit qu'il ne joint rien, et l'hôte l'en empêche. Les deux, pas l'un ou l'autre.

Lance un cycle complet :

```bash
./run-cycle.sh OneStart
cat data/out/report.md
```

Tu obtiens un rapport produit sans clé, sans réseau et sans appel de modèle payant. Le code de
sortie vaut 0 si un candidat a été produit, 1 s'il a été refusé. Les deux sont normaux.

Vérifie la santé :

```bash
docker compose run --rm intel health --state /data/state/last-run.json
```

Attendu : `OK: last run produced a candidate 12s ago (mode fixture)`.

Si cette étape ne passe pas, aucune des suivantes ne passera, et elles échoueront en consommant
du quota. Ne saute pas.

---

## Étape 2. Lire la liste des destinations

Toujours sans réseau, demande au collecteur ce qu'il enverrait :

```bash
docker compose --profile online run --rm intel-online \
    run --mode collect --dry-run \
    --family OneStart \
    --seed 246e8d6a000000000000000000000000000000000000000000000000f7c9c012
```

Sortie :

```
DRY RUN -- nothing will be sent. mode=collect outbound=www.hybrid-analysis.com
mode=collect dry_run=True hybrid_analysis_key=unset triage=off llm=off publish=off
  would GET https://www.hybrid-analysis.com/api/v2/overview/246e8d6a...
```

Lis cette liste. C'est exactement ce que tu vas autoriser la machine à joindre.

Remarque ce qui n'y figure pas. Aucun `POST`. Le transport n'a pas de corps de requête, donc il
ne peut pas envoyer de fichier. La lecture seule sur Hybrid Analysis est une propriété du code,
pas une promesse dans un document, et cette commande est l'endroit où tu peux le constater.

---

## Étape 3. La collecte réelle

Une fois le vetting Hybrid Analysis accordé, mets la clé dans `.env` :

```bash
nano .env
# HYBRID_ANALYSIS_API_KEY=ta-clé-ici
```

Le fichier est en LF. Si tu l'édites depuis Windows, garde les fins de ligne Unix, sinon chaque
valeur reçoit un retour chariot en fin de chaîne et la clé est rejetée sans message utile.

Teste la clé avant de lancer un cycle :

```bash
docker compose --profile online run --rm intel-online \
    run --mode collect --family OneStart --seed <un sha256 public>
```

Puis passe par le script, qui ajoute la sauvegarde, la purge du cache et la rotation des
journaux :

```bash
MODE=collect ./run-cycle.sh OneStart <sha256> <sha256>
```

Fais tourner deux ou trois familles à la main avant de planifier quoi que ce soit. Tu veux
savoir à quoi ressemble un rapport normal avant d'en recevoir pendant ton sommeil.

---

## Étape 4. La planification

```bash
./install-systemd.sh
```

Le script affiche les quatre unités et n'écrit rien. Lis-les, puis installe :

```bash
sudo ./install-systemd.sh --write
systemctl list-timers 'puakiller-intel*'
```

Deux minuteurs sont installés. `puakiller-intel.timer` lance un cycle par jour, avec un délai
aléatoire de trente minutes pour ne pas taper le fournisseur à minuit pile comme tout le monde.
`puakiller-intel-health.timer` vérifie toutes les heures que des cycles ont bien lieu.

Le second existe parce que la panne réaliste est silencieuse. Un planificateur qui s'arrête ne
produit ni erreur, ni ligne de journal. Il ne produit rien, ce qui ressemble exactement à une
semaine calme.

Variables utiles :

```bash
ON_CALENDAR='Mon *-*-* 04:00:00' sudo -E ./install-systemd.sh --write
RUN_AS=puakiller sudo -E ./install-systemd.sh --write
```

---

## La publication ne se fait pas ici

Le serveur collecte et évalue. Il n'ouvre ni Issue ni Draft PR.

Cette machine détient les clés fournisseur. Lui donner en plus un jeton d'écriture sur le dépôt
reviendrait à mettre les deux moitiés de la séparation dans le même sac. La publication tourne
dans GitHub Actions, workflow `intel-propose`, ou depuis ton poste :

```bash
cd intel-factory
PYTHONPATH=src python3 -m puakiller_intel publish \
    --bundle ../deploy/data/out/bundle.json \
    --repo ZER0Nep/puakiller \
    --root ..
```

Sans `--execute`, rien n'est envoyé. La commande affiche le plan et s'arrête.

Ne mets pas de `GITHUB_TOKEN` dans `deploy/.env`. Un test échoue si tu le fais.

---

## Vivre avec

### Où sont les choses

```
deploy/data/out/report.md        le dernier rapport, écrit pour être lu par un humain
deploy/data/out/bundle.json      le seul fichier que le publieur a le droit de lire
deploy/data/state/last-run.json  ce que lit le healthcheck
deploy/data/state/run.lock       présent seulement pendant un cycle
deploy/data/logs/run-cycle.log   la transcription côté hôte, tournée à 10 Mo, 5 copies
deploy/data/backups/<horodatage> le catalogue, copié avant chaque cycle
```

### Les commandes du quotidien

```bash
# Le dernier verdict
docker compose run --rm intel health --state /data/state/last-run.json

# Le journal
tail -f data/logs/run-cycle.log

# Ce que le cache occupe
docker compose run --rm intel cache

# Purger le cache à la main
docker compose run --rm intel cache --purge-older-than 30

# Relancer un cycle maintenant
sudo systemctl start puakiller-intel.service
journalctl -u puakiller-intel.service -n 50
```

### Lire un résultat

`report.md` donne le verdict, le score et son détail, les objections du critic, les collisions
bénignes testées, les sources publiques et les versions de prompt.

Trois issues possibles. Score inférieur à 40, le candidat est refusé et rien n'est publié. Entre
40 et 69, une Issue part en triage humain. À partir de 70, une Draft PR propose des indicateurs
exacts. Aucun de ces chemins n'écrit une règle. Une règle reste écrite à la main.

---

## Quand ça casse

| Ce que tu vois | Ce que c'est | Le geste |
|---|---|---|
| `Permission denied` sur `/data/...` | `deploy/data` n'appartient pas à l'uid 10001 | `sudo chown -R 10001:10001 data` |
| `env file .env not found` | Le fichier n'a pas été copié | `cp .env.example .env && chmod 600 .env` |
| `mode 'collect' needs HYBRID_ANALYSIS_API_KEY` | Clé absente, ou fins de ligne CRLF dans `.env` | Vérifie avec `file .env`, réécris en LF |
| `skipped: another run holds run.lock` | Un cycle tourne déjà | Rien. Le prochain tick reprendra |
| `warning: run.lock was stale and has been taken over` | Un cycle précédent est mort sans nettoyer | Le planificateur s'est rétabli seul, mais regarde `journalctl` pour savoir pourquoi |
| Sortie 1 d'un cycle | Le candidat a été refusé | Rien. C'est le résultat normal, et l'unité systemd ne passe pas en échec |
| `UNHEALTHY: no run recorded` | Le minuteur n'a jamais tiré | `systemctl status puakiller-intel.timer` |
| `UNHEALTHY: the last run finished 200000s ago` | Les cycles se sont arrêtés | `journalctl -u puakiller-intel.service` |
| `prompt file not found` | Le montage `../prompts` manque | Lance les commandes depuis `deploy/`, pas ailleurs |
| `--triage was passed but TRIAGE_ENABLED is not set` | Un seul des deux interrupteurs | Mets les deux, ou aucun |
| `REFUSED: refusing input that carries non-public data` | Une source publique contenait un chemin utilisateur, une IP privée ou une adresse mail | C'est le filtre qui fait son travail. Ne nettoie pas la source à la main, retire la graine |

Le dernier cas mérite un mot. Le message nomme la classe de donnée, jamais la valeur. Si tu as
besoin de savoir laquelle, va voir la source publique toi-même. Le programme refuse de la
recopier, y compris dans son propre message d'erreur.

---

## Sauvegarde et restauration

Une copie du catalogue est prise avant chaque cycle, validée comme JSON et accompagnée d'un
fichier de sommes. Quatorze copies sont conservées, réglable avec `BACKUP_KEEP`.

Pour restaurer :

```bash
ls data/backups
cd data/backups/20260902T041500Z
sha256sum -c SHA256SUMS
cp rules/catalog.json ../../../../rules/catalog.json
cd -
python3 ../scripts/verify-generated.py
```

La dernière commande est celle qui compte. Elle prouve que le catalogue restauré recompile
exactement la région de règles que portent les deux scripts distribués. Si elle échoue, le
catalogue et les scripts ne sont plus d'accord, et rien ne doit être distribué avant que ce soit
réglé.

---

## Mettre à jour

```bash
cd puakiller
git pull
cd deploy
docker compose build
./run-cycle.sh OneStart          # un cycle fixture pour vérifier
```

Refais toujours un cycle en mode fixture après une mise à jour. Il ne coûte rien et il attrape
une image cassée avant que le minuteur ne le fasse à quatre heures du matin.

---

## Désinstaller

```bash
sudo systemctl disable --now puakiller-intel.timer puakiller-intel-health.timer
sudo rm /etc/systemd/system/puakiller-intel*.service /etc/systemd/system/puakiller-intel*.timer
sudo systemctl daemon-reload
docker compose down --rmi local
```

`deploy/data` reste en place. Supprime-le à la main quand tu es sûr de ne plus vouloir les
rapports et les sauvegardes.

---

## Activer Triage, plus tard

Triage est optionnel et le reste. La chaîne fonctionne entièrement sans lui.

Son intérêt tient en une ligne. Sa recherche est un `GET`, donc il accepte un nom de famille
comme graine, ce que Hybrid Analysis ne permet pas sur ce projet. Tu passes de "j'ai un hash" à
"j'ai un nom".

Il faut les deux interrupteurs :

```bash
# dans .env
TRIAGE_ENABLED=true
TRIAGE_API_KEY=ta-clé
```

```bash
MODE=collect TRIAGE=true ./run-cycle.sh OneStart
```

Un seul des deux est un refus explicite. Un fournisseur optionnel qui s'active tout seul n'est
pas optionnel.

Une réserve honnête avant de l'activer. Les cassettes de test ont été écrites à la main depuis
la forme documentée de l'API, faute d'accès au service. Le premier run réel doit être un
`--dry-run`, et l'allowlist de champs revérifiée contre une réponse authentique.

---

## Ce que cette machine ne peut pas faire

Utile à relire le jour où quelqu'un demande si elle est dangereuse.

Elle ne peut pas soumettre d'échantillon. Le transport n'a pas de corps de requête.
Elle ne peut pas écrire dans le dépôt. Aucun jeton GitHub n'y réside.
Elle ne peut pas modifier son propre code. L'image est montée en lecture seule.
Elle ne peut pas devenir root. `cap_drop: ALL` et `no-new-privileges`.
Elle ne peut pas produire de règle. Elle produit des candidats sourcés, relus par une personne.
Elle ne joint rien en mode par défaut. `network_mode: none`.
