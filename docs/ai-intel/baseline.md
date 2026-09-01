# Baseline PUAKILLER — Phase 0

Date (UTC) : 2026-09-01
Dépôt : `https://github.com/ZER0Nep/puakiller`
Commit de référence : `ff43b48e9622c422b7337198aa2730f1ce084bd9` (`main`, seule branche)
Copie de travail : `C:\Users\timit\Downloads\puakiller`
Kit d'architecture : `C:\Users\timit\Downloads\puakiller-ai-architecture-kit\puakiller-ai-architecture-kit` (hors dépôt)
Cible d'hébergement de l'Intel Factory : **Linux** (décision utilisateur, 2026-09-01)

**Aucune règle ni logique de suppression n'a été modifiée. Aucun fichier du dépôt n'a été modifié.** Seuls `docs/ai-intel/baseline.md` et `docs/ai-intel/phase1-plan.md` ont été créés.

---

## 1. Baseline de tests — VERTE

Tests exécutés localement, sur les deux moteurs. **Tous statiques** : `Test-PuaRules.ps1` lit les règles via l'AST (`SafeGetValue()`) sans jamais exécuter les scripts de remédiation ; les autres n'exécutent que des helpers isolés sur des fixtures inoffensives. Aucune remédiation déclenchée.

| Test | PS 5.1 | PS 7.6.5 | Assertions |
|---|:--:|:--:|---|
| `tests/Test-PuaRules.ps1` | PASS | PASS | 322 checks |
| `tests/Test-StatsUpdater.ps1` | PASS | PASS | fixture offline |
| `tests/Test-OneBrowserGuard.ps1` | PASS | PASS | garde alias `OB` |
| `tests/Test-ShiftBrowserGuard.ps1` | PASS | PASS | garde alias `Shift` |
| `tests/Test-Logging.ps1` | PASS | PASS | 14 checks |
| `tests/Test-ExecutionContext.ps1` | PASS | PASS | 24 checks |
| parse-check (tous `.ps1`) | OK | OK | 0 erreur |
| lint « pas de construction PS7-only » | OK | OK | 0 occurrence |

**12/12 verts sur les deux moteurs. 360 assertions.**

### Commandes de reproduction

```powershell
# Depuis la racine du dépôt. Windows PowerShell 5.1 (cible de déploiement)
foreach ($t in 'Test-PuaRules','Test-StatsUpdater','Test-OneBrowserGuard','Test-ShiftBrowserGuard','Test-Logging','Test-ExecutionContext') {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tests\$t.ps1"
}

# PowerShell 7
foreach ($t in 'Test-PuaRules','Test-StatsUpdater','Test-OneBrowserGuard','Test-ShiftBrowserGuard','Test-Logging','Test-ExecutionContext') {
    pwsh -NoProfile -File "./tests/$t.ps1"
}
```

Environnement : `pwsh` 7.6.5, `powershell` 5.1, Python 3.13.5. Pas besoin d'une CI Windows pour la baseline.

Le projet n'utilise **pas** Pester : chaque test est un script autonome qui `exit 0` / `exit 1`. À conserver (dépendance zéro).

---

## 2. Carte des fichiers

| Fichier | Lignes | Rôle |
|---|---:|---|
| `hosted-removal.ps1` | 1297 | Script distribué (`script.nep.red`). **Source canonique des règles** — celui que `Test-PuaRules.ps1` lit en premier. |
| `PUAKILLER-LOCAL.ps1` | 1296 | Variante locale. Règles identiques ; 4 écarts de comportement (§5). |
| `scripts/Update-Stats.ps1` | 69 | Compteur de fetches du `README.md`. Sans lien avec la détection. |
| `tests/Test-PuaRules.ps1` | 229 | Sûreté (faux positifs) + détection + **parité** + contrat de relance. Le test critique. |
| `tests/Test-ExecutionContext.ps1` | 73 | Résolveur de contexte SYSTEM / admin / interactif. |
| `tests/Test-Logging.ps1` | 79 | Log `ProgramData`, append/fallback. |
| `tests/Test-OneBrowserGuard.ps1` | 47 | Garde d'évidence sur l'alias court `OB`. |
| `tests/Test-ShiftBrowserGuard.ps1` | 39 | Garde d'évidence sur l'alias générique `Shift`. |
| `tests/Test-StatsUpdater.ps1` | 39 | Fixture offline de l'updater. |
| `tests/README.md` | 94 | Doctrine de contribution : « quand vous ajoutez un PUA ». |
| `.github/workflows/tests.yml` | 91 | CI `windows-latest`, 12 étapes + parse-check + lint PS5.1. |
| `.github/workflows/update-stats.yml` | 39 | Cron `*/15`, `contents: write`, commit+push sur `main`. |
| `README.md` | 22 | Marqueurs `<!-- stats:start/end -->`. |

Aucun `CLAUDE.md` ni `AGENTS.md` dans le dépôt. Seules instructions contributeur : `tests/README.md` et le commentaire d'en-tête de `$Puas`.

### Encodage et fins de ligne — critique pour un compilateur Linux

| Constat | Valeur |
|---|---|
| Fins de ligne, arbre de travail Windows | **CRLF à 100 %** (1297/1297, 1296/1296, 229/229, 69/69) |
| BOM | **aucun** sur les 4 fichiers testés |
| `.gitattributes` | **ABSENT** |
| `core.autocrlf` (local) | `true` |

Conséquence : le dépôt stocke vraisemblablement du **LF**, converti en CRLF au checkout Windows. Un compilateur exécuté sur le **serveur Linux** verra du LF et écrira du LF ; le même compilateur sur le poste Windows verra du CRLF. **Sans `.gitattributes`, « byte-for-byte identique » n'est pas une propriété bien définie** : elle dépend de la plateforme.

→ Le byte-for-byte doit se définir **sur le blob Git normalisé (LF)**, pas sur le fichier de l'arbre de travail, et un `.gitattributes` doit figer la règle avant le premier commit du compilateur. Traité en C1bis du plan de phase 1.

---

## 3. Champs réels du modèle `$Puas`

Emplacement : `hosted-removal.ps1:198-263`, `PUAKILLER-LOCAL.ps1:199-264`. **11 entrées.**

### 3.1 Champs déclaratifs — les seuls à migrer

| Champ | Type | Obligatoire | Sémantique réelle (vérifiée dans le code) |
|---|---|:--:|---|
| `Name` | string | oui | Nom exact du dossier d'installation. Balayage **inconditionnel** de `%LOCALAPPDATA%\<Name>`, `%APPDATA%\<Name>`, `…\Programs\<Name>`, Start-Menu, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData%` (`:1050-1062`). **Champ le plus destructeur du modèle.** |
| `Label` | string | oui | Affichage bannière/vérification. `''` masque l'entrée (`:264`). |
| `Rx` | regex | oui | Regex insensible à la casse sur chemins de processus, valeurs `Run`, App Paths, classes COM, entrées de désinstallation, tâches, raccourcis, droppers, items Temp (`:575,659,672,1216,1220`). |
| `Proc` | string[] | oui | Noms de processus **exacts** à tuer, sans `.exe` (`:520`). Jamais de nom générique — imposé par test. |
| `Pub` | regex \| `''` | oui | Regex éditeur pour Ajout/Suppression de programmes et évidence d'alias. |
| `Nw` | bool | oui | Nettoyage additionnel des dossiers Temp NW.js `nw*` dont le manifeste matche (`:663-672`). |
| `Harden` | string[] | oui | Dossiers relatifs à `AppData` scellés contre réinstallation sous `-Harden` (`:1242`). |
| `Aliases` | string[] | non | Noms de dossiers additionnels. **Supprimés uniquement si évidence statique** (filename / hash / signer) trouvée dedans — `Test-PuaAliasDir` (`:1054-1071`). Le garde-fou qui rend `OB` et `Shift` sûrs. |
| `RegNames` | string[] | non | Clés registre vendeur, supprimées seulement sur évidence fichier ou clé primaire distinctive (`:1068-1086`). |
| `Hashes` | string[] | non | SHA-256 vérifiés par hachage **statique** dans les dossiers alias gardés et les exécutables téléchargés — jamais d'exécution (`:480-486`). |

### 3.2 Champs injectés à l'exécution — NE PAS migrer

`Dirs` et `RegPaths` ne sont **pas** des champs de règle. Ils sont calculés puis réécrits dans la hashtable :

```powershell
# hosted-removal.ps1:1085-1088
        $pua.RegPaths = if ($evidence) { $regPaths } else { @() }
    } else { $pua.RegPaths = @() }
    $pua.Dirs = $pd
    Invoke-PuaSweep -Name $pua.Name -Rx $pua.Rx -Proc $pua.Proc -Dirs $pua.Dirs -RegPaths $pua.RegPaths -Hashes $pua.Hashes -Pub $pua.Pub -Nw $pua.Nw
```

Le catalogue porte donc **10 champs, pas 12**. `$Puas` est muté en cours d'exécution ; l'extraction statique par AST (déjà utilisée par les tests) capture exactement le sous-ensemble déclaratif. C'est la bonne frontière.

### 3.3 Les 11 entrées

| # | `Name` | `Label` | Optionnels | Note |
|---:|---|---|---|---|
| 1 | `OpenBook` | OpenBook | `Nw=$true` | seule entrée NW.js |
| 2 | `ConvertMate` | ConvertMate | — | `Pub` pinné (Amaryllis) |
| 3 | `PDFEditor` | PDFEditor | — | nom générique ; désambiguïsé par `Pub` |
| 4 | `EPISoftware` | EpiBrowser | — | `Name` ≠ `Label` |
| 5 | `OneStart.ai` | OneStart | — | arbre vendeur Local |
| 6 | `OneStart` | `''` | — | **entrée masquée**, couvre `%APPDATA%\OneStart` |
| 7 | `ProOneStartHub` | ProOneStartHub | — | `Proc=@()`, `Pub=''` — ancre de régression |
| 8 | `OneBrowser` | OneBrowser | `Aliases=@('OB')`, `RegNames`, `Hashes` (1) | seule entrée à hash |
| 9 | `ManualFinder` | ManualFinder | — | IOC de compromission (infostealer) |
| 10 | `KitchenCanvas` | KitchenCanvas | — | `Rx` couvre le dropper randomisé `RecipeSetup[-_]` |
| 11 | `ShiftBrowser` | ShiftBrowser | `Aliases=@('Shift')`, `RegNames` | `Proc=@()` volontairement — produit légitime homonyme |

Chaque entrée non triviale porte un **bloc de commentaire de provenance** (pcrisk, todyl, any.run, Joe Sandbox, Sophos, Unit 42, G DATA, file.net) avec IOC, chemins, tâches, clés registre, SHA-256 tronqués. **La provenance existe déjà — en prose, non structurée.** Gisement direct pour le champ `provenance[]` du catalogue.

### 3.4 `$BadSigners`

`hosted-removal.ps1:270-280`, **10 sujets**. Compilé immédiatement :

```powershell
# :281
$BadSignerRx = '(?i)(' + (($BadSigners | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
```

**Un compilateur déterministe avec échappement existe déjà dans le produit**, et c'est le bon modèle (littéraux exacts → `[regex]::Escape` → alternance). Consommé par `Invoke-CertSweep` (`:1101-1196`), qui supprime des racines d'application entières dans les emplacements inscriptibles — **le chemin le plus destructeur du script**. D'où le commentaire `:266-268` : liste volontairement limitée à des sujets de sociétés-écrans distinctifs.

### 3.5 Pulse — un second jeu de règles, hors `$Puas`

Pulse n'est **pas** dans `$Puas`. Codé en dur :

| Variable | Ligne (hosted) |
|---|---|
| `$PulseRegex` | 344 |
| `$PulseGuids` | 346 |
| `$procNames` | 683 |
| `$genericExe` | 684 |

`$PulseRegex` est utilisé sur ~25 sites d'appel (processus, modules chargés, services, `Run`, COM, désinstallation, raccourcis, Temp, tâches). `$genericExe = @('updater','enterprise_companion','setup')` n'est mortel qu'en conjonction d'un chemin matchant `$PulseRegex` (`:692`) — garde correcte.

`Test-PuaRules.ps1` vérifie la parité de `$PulseRegex`. Le catalogue devra décider s'il absorbe Pulse ou le laisse hors périmètre (§11, Q2).

---

## 4. Champs réels de la télémétrie

`Send-Stat` — `hosted-removal.ps1:141-168` :

```powershell
function Send-Stat([string]$Phase) {
    if ($NoStats -or -not $StatsUrl) { return }
    try {
        $payload = @{
            v        = $ScriptVersion          # '1.8.0'
            runId    = $RunId                  # -StatId, sinon [guid]::NewGuid()
            phase    = $Phase
            action   = if ($DryRun) { 'preview' } else { 'remove' }
            headless = [bool]$Headless
            noelev   = [bool]$NoElevate
            harden   = [bool]$Harden
            certscan = [bool](-not $SkipCertScan)
            admin    = (Test-Admin)
            removed  = $script:Removed
            errors   = $script:Errors
            os       = [string][System.Environment]::OSVersion.Version
            ps       = [string]$PSVersionTable.PSVersion
        } | ConvertTo-Json -Compress
        # ... HttpWebRequest POST, application/json, Timeout 5000
    } catch {}
}
```

**13 clés.** Transport : `System.Net.HttpWebRequest`, POST, timeout 5 s, `catch {}` silencieux, aucune persistance disque, aucun retry.

`$StatsUrl` :
- `hosted-removal.ps1:41` → `'https://script.nep.red/stat'`
- `PUAKILLER-LOCAL.ps1:42` → `''` → **la variante locale n'émet jamais de statistique.**

`-NoStats` (`:9`) est validé, propagé à la relance 32→64 bits (`$reArgs`), à l'élévation (`$extra`) et au fallback de téléchargement — les trois chemins sont **testés** (`Test-PuaRules.ps1`, §RELAUNCH CONTRACT).

### Conformité aux invariants du kit

| Invariant | Statut | Preuve |
|---|:--:|---|
| I11 — `-NoStats` bloque toute requête | **OK** | garde en première ligne de `Send-Stat` |
| I12 — payload par allowlist sur objet neuf | **OK** | hashtable littérale, jamais de sérialisation d'objet d'exécution |
| I13 — l'échec n'affecte pas la remédiation | **OK** | `catch {}`, timeout 5 s |
| Contrôle 5 — pas de retry persistant sur disque | **OK** | aucune persistance |
| Aucune famille / hash / IOC / chemin / host / user | **OK** | 13 scalaires de configuration et compteurs agrégés |

**L'esprit de `SECURITE-ET-TELEMETRIE.md` est déjà respecté par l'implémentation existante.** Aucune fuite d'observation SOC.

### Écart avec `telemetry.schema.json`

Le schéma du kit est **clos** (`additionalProperties: false`) et ne décrit pas le payload réel :

| Payload réel | Schéma du kit | Verdict |
|---|---|---|
| `v` | `version` | **nom différent** |
| `runId` | `runId` | OK |
| `action` (`preview`/`remove`) | `mode` (`preview`/`remove`) | **nom différent**, valeurs identiques |
| `ps` | `powershell` | **nom différent** |
| `headless`, `admin`, `removed`, `errors`, `os` | idem | OK |
| `phase` | — | **absent** → rejeté |
| `noelev` | — | **absent** → rejeté |
| `harden` | — | **absent** → rejeté |
| `certscan` | — | **absent** → rejeté |
| — | `ruleset` (mentionné dans la doc) | absent des deux |

**7 clés sur 13 feraient échouer la validation.** Aucune n'est une donnée interdite : 4 booléens de configuration (`noelev`, `harden`, `certscan`) et une chaîne de phase. Le schéma du kit a été écrit **avant** d'avoir vu le payload : c'est le schéma qui doit s'aligner sur le produit, pas l'inverse — sinon la phase de télémétrie devient une modification de comportement distribué, ce que la phase 0 interdit.

`phase` est le seul champ à examiner : sa cardinalité doit être bornée par un `enum` (valeurs à énumérer sur les sites d'appel de `Send-Stat`) pour rester une donnée de configuration et non un canal de texte libre.

---

## 5. Écarts entre les deux scripts

`diff` complet : **17 lignes**, 4 écarts. Aucun ne touche les règles.

| # | Ligne (hosted) | Écart | Nature |
|---:|---|---|---|
| 1 | `:18` (local seulement) | `$NoElevate = $true` forcé dans `PUAKILLER-LOCAL.ps1` | intentionnel |
| 2 | `:19` | Défaut sans argument : local ajoute `$Harden = $true`, hosted non | intentionnel |
| 3 | `:41` | `$StatsUrl` : hosted `'https://script.nep.red/stat'`, local `''` | intentionnel |
| 4 | `:1267-1279` | Déchargement de ruche : hosted 6 tentatives + double GC + message d'info ; local 3 tentatives | **hosted plus robuste — local semble en retard** |

### Preuve d'identité des règles

```
hosted-removal.ps1  [198-281]  sha256 = 6f49976cf319fe21…
PUAKILLER-LOCAL.ps1 [199-282]  sha256 = 6f49976cf319fe21…
```

**La région de règles est déjà byte-for-byte identique entre les deux scripts.** Fait le plus important de cette phase 0 : la preuve d'équivalence exigée en phase 1 est atteignable trivialement, et le compilateur a une cible unique et non ambiguë.

---

## 6. Couverture des tests et lacunes

### Déjà couvert, et correctement

- **Faux positifs** : `$BENIGN_NAMES` (≈ 60 entrées, avec les pièges volontaires `OB`, `Shift`, `PDF Editor`, `Recipe Setup.exe`), `$BENIGN_PROCS` (≈ 30), `$BENIGN_PUBLISHERS` (≈ 22 dont `Work Product Solutions LLC` et `Shift Technologies Inc.`, très proches des signataires bloqués). **Le corpus bénin machine-readable exigé par le kit existe déjà.**
- **Régression de détection** : `$MAL_RX`, `$MAL_PULSE`, `$MAL_FOLDERS`, `$MAL_ALIASES`, `$MAL_PROCS`, `$MAL_HASHES`, `$MAL_PUBLISHERS`.
- **Parité** sur `$Puas`, `$BadSigners`, `$PulseRegex`.
- **Assertions négatives ciblées** : `OB` et `Shift` ne doivent jamais être des `Name` inconditionnels ; `shift` ne doit jamais être un `Proc`.
- **Contrat de relance** : `-SkipCertScan`, `-NoStats`, `-LogPath` survivent aux deux handoffs.
- **Compatibilité PS 5.1** : lint anti-constructions PS7-only en CI.

### Lacunes

| # | Lacune | Détail | Sévérité |
|---:|---|---|---|
| L1 | `Label` hors parité | `Norm()` (`Test-PuaRules.ps1:196`) concatène `Name\|Rx\|Proc\|Pub\|Nw\|Harden\|Aliases\|RegNames\|Hashes` — **`Label` absent**. Les deux scripts pourraient afficher des bannières divergentes sans signal CI. | Faible (cosmétique), à combler en C0 : gratuit. |
| L2 | Format des `Hashes` non validé | Aucun test n'impose 64 caractères hex minuscules. Un hash mal collé (majuscules, espace, tronqué) passerait la CI et rendrait la garde d'alias **silencieusement inopérante**. | **Moyenne** |
| L3 | Pas de test de payload télémétrie | Aucun champ sentinelle (`hostname`, `sha256`, `path`), aucun snapshot. Contrôles 2 et 3 de `SECURITE-ET-TELEMETRIE.md` non implémentés. | **Moyenne** — conformité actuelle correcte mais non verrouillée. |
| L4 | `Name` sans garde | Contrairement à `Aliases`, `Name` déclenche une suppression **inconditionnelle**. Rien n'empêche structurellement un futur `Name` générique ; seul `$BENIGN_NAMES` protège, et il faut penser à l'alimenter. | **Moyenne** — risque destructeur n° 1 du modèle. |
| L5 | `$puaBanner` non testé | Dérivé de `Label` ; aucune assertion. | Faible |
| L6 | Pas de test d'idempotence des règles | Rien ne vérifie l'unicité des `Name` ni qu'un `Rx` n'avale une autre entrée. | Faible |

---

## 7. Workflows et permissions GitHub

### `.github/workflows/tests.yml`

- Déclencheurs : `push` sur `main`, `pull_request`. Runner `windows-latest`.
- **Aucun bloc `permissions:`** → hérite du défaut du dépôt (potentiellement read-write). Aucun secret consommé, aucune écriture effectuée : impact réel nul, mais **`permissions: contents: read` devrait être déclaré explicitement** — durcissement à coût zéro, conforme au moindre privilège du kit.

### `.github/workflows/update-stats.yml`

- Cron `*/15 * * * *` + `workflow_dispatch`. `concurrency` avec `cancel-in-progress`.
- `permissions: contents: write`. Commit et push directs sur `main`.
- Exécute `scripts/Update-Stats.ps1` : requête vers `https://script.nep.red/stat`, **avec repli sur un tiers `https://r.jina.ai/https://script.nep.red/stat`**.

**Observation de sécurité.** Ce job lit du contenu réseau externe *et* détient un token d'écriture — exactement le couplage que `ARCHITECTURE.md` interdit entre Job A (collecte, aucun droit d'écriture Git) et Job D (publication, aucune donnée brute). L'impact est aujourd'hui **fortement borné** et le script est bien écrit :

- regex ancrée sur un libellé précis (`class="n"` … `total fetches`) ;
- `-replace '\D',''` puis `[int64]` — seuls des chiffres survivent ;
- `throw` si le motif est absent ou le nombre vide (**fail closed**) ;
- aucun HTML de l'endpoint copié dans le dépôt ;
- écriture confinée entre les marqueurs `<!-- stats:start/end -->`.

Résidu : le **repli `r.jina.ai`**, tiers en position de rendre le contenu, dans un job pouvant pousser sur `main`. Pire cas réalisable : un compteur faux — le contenu ne peut pas s'échapper de `[int64]`. Dette acceptée à documenter, ou à retirer si le CDN direct suffit. **Pas un blocage de phase 1.**

Le commit `[skip ci]` du compteur explique les 100+ commits automatiques récents : le signal humain est noyé. À prendre en compte pour le `verify-generated`.

---

## 8. Impact de la cible Linux

Le serveur distant qui hébergera l'Intel Factory tournera sous **Linux**. Conséquences vérifiées :

| Sujet | Impact | Traitement |
|---|---|---|
| Fins de ligne | **Réel et bloquant pour le byte-for-byte** (§2). Le compilateur produit LF sous Linux, CRLF sous Windows, sans `.gitattributes`. | Figer via `.gitattributes` (`*.ps1 text eol=crlf` ou `eol=lf`, à trancher — Q5) **avant** le premier commit du compilateur. Comparer sur le blob Git normalisé, pas sur l'arbre de travail. |
| Langage du compilateur | Aucun. Python 3 stdlib tourne à l'identique. | Standard-library-first confirmé. |
| Vérification croisée de l'échappement | `pwsh` existe sous Linux (`powershell-7`) → le test de propriété de C3 peut valider l'échappement **réellement en PowerShell** sur le serveur. | Ajouter `pwsh` à l'image Docker de dev, ou restreindre ce test à la CI Windows. Q6. |
| CI des tests PowerShell | Aucun. `tests.yml` reste sur `windows-latest` — c'est la cible de déploiement (PS 5.1). | Inchangé. Ne **pas** migrer ces tests vers un runner Linux. |
| Conteneur | Neutre. `ARCHITECTURE.md` prévoit déjà une image non-root + `compose.yaml`. | Phase 6. |
| Sensibilité à la casse du système de fichiers | Linux est sensible à la casse, Windows non. Un catalogue référençant `EPISoftware` vs `episoftware` se comporterait différemment côté outillage. | Le compilateur doit comparer les `Name`/`Aliases` en casse-insensible **explicitement**, jamais s'appuyer sur le système de fichiers. |

---

## 9. Invariants à préserver

**Détection / remédiation**
- I1 — Aucune règle ni logique de suppression ne change sans approbation humaine explicite.
- I2 — Deux compilations successives byte-for-byte identiques, **sur la même plateforme et via le blob Git normalisé** (§8).
- I3 — Scripts autonomes, PS 5.1 **et** 7. Lint anti-PS7-only maintenu.
- I4 — Aucune regex issue d'un LLM ; motif complexe ⇒ `requires_manual_regex: true`.
- I15 — *(observé)* `Name` déclenche une suppression **inconditionnelle** ; `Aliases` exige une évidence statique. **Cette asymétrie est le cœur de la sûreté du produit et ne doit jamais être aplatie par une refactorisation.**
- I16 — *(observé)* Aucun nom de processus générique dans `Proc` ; les exécutables génériques se matchent par chemin via `Rx`.
- I17 — *(observé)* Les hashes servent d'**évidence de garde**, jamais de déclencheur de suppression autonome, et sont calculés statiquement.

**Télémétrie**
- I11 — `-NoStats` bloque toute requête. **Déjà vérifié.**
- I12 — Payload par allowlist sur objet neuf. **Déjà vérifié.**
- I13 — L'échec n'affecte pas la remédiation. **Déjà vérifié.**
- I14 — L'IP source reste visible du serveur HTTP ; à documenter, pas à masquer.
- I18 — *(observé)* `PUAKILLER-LOCAL.ps1` n'émet aucune statistique (`$StatsUrl = ''`). À préserver explicitement.

**Intel Factory** (phases ≥ 2)
- I5 — Aucune méthode `submit` / `upload` dans l'adaptateur Hybrid Analysis.
- I6 — Validateur sans réseau ni LLM.
- I7 — Publisher sans documents bruts ni clés provider.
- I8 — Chaque indicateur accepté référence ≥ 1 preuve publique.
- I9 — Mode `fixture` sans secret ; mode live refusant de démarrer sans secret requis.
- I10 — Triage désactivé par défaut.

---

## 10. Risques

| # | Risque | Impact | Mitigation |
|---:|---|---|---|
| R1 | Aplatir l'asymétrie `Name` / `Aliases` | Un alias générique promu en `Name` supprimerait des dossiers légitimes | Le schéma doit rendre l'asymétrie **structurelle** : `Aliases` exige un `guard` non vide ; un `Name` court ou présent dans le corpus bénin est refusé à la compilation. |
| R2 | Divergence des deux scripts | Le compilateur unifierait un écart intentionnel | Les 4 écarts sont recensés (§5) et hors région de règles. Région de règles déjà identique — risque neutralisé pour la phase 1. |
| R3 | Échappement de littéraux | Un littéral mal échappé transforme une correspondance exacte en motif large ⇒ suppression massive | `[regex]::Escape` est déjà le modèle en place (`:281`). Le compilateur doit le reproduire à l'identique, avec tests de propriété et vérification croisée en exécutant PowerShell. |
| R4 | Regex complexes non générables | 7 des 11 `Rx` sont des alternances avec ancres `\b`, échappements et versions littérales (`ShiftBrowser`, `KitchenCanvas`) | **Ne pas tenter de les générer.** Elles sont écrites à la main avec un raisonnement de sûreté documenté. Le catalogue les stocke **verbatim**, marquées `requires_manual_regex: true` ; le compilateur les recopie sans les reconstruire. |
| R5 | Édition manuelle d'un bloc généré | Perte silencieuse de la correction | `verify-generated` bloquant en CI. |
| R6 | Perte des commentaires de provenance | Les blocs portent l'analyse de sûreté (pourquoi `Proc=@()` pour ShiftBrowser, pourquoi pas de `Pub` pour KitchenCanvas). Une génération naïve les détruirait. | Le catalogue porte `rationale` et `provenance[]` ; le compilateur **doit ré-émettre les commentaires**. Un bloc généré sans commentaires est un échec de la phase 1, pas un détail cosmétique. |
| R7 | Élargissement du payload de stats | Fuite d'observation SOC | Ajouter le test à champs sentinelles (L3) **avant** toute modification de `Send-Stat`. |
| R8 | Bruit de commits automatiques | 100+ commits `[skip ci]` masquent les changements réels | `verify-generated` cible les régions de règles, pas le `README.md`. |
| R9 | Le schéma du kit ne décrit pas le produit | Aligner le produit sur le schéma changerait le comportement distribué | Aligner le **schéma** sur le produit (§4). Décision requise (Q3). |
| R10 | Fins de ligne multiplateformes | Le byte-for-byte échoue ou passe selon la plateforme du compilateur | `.gitattributes` avant tout commit du compilateur ; comparaison sur blob Git normalisé (§2, §8). |

---

## 11. Statut phase 0

| Item du mandat | Statut |
|---|---|
| 1. Lire le kit (7 docs + 3 schémas + exemple) | **FAIT** |
| 2. Inspecter la structure et les instructions locales | **FAIT** — 17 fichiers ; aucun `CLAUDE.md`/`AGENTS.md` dans le dépôt |
| 3. Localiser `$Puas`, `$BadSigners`, `Send-Stat`, `-NoStats`, tests, workflows | **FAIT** — §3, §4, §6, §7, avec numéros de ligne |
| 4. Exécuter les tests sans remédiation destructive | **FAIT** — 12/12 verts, PS 5.1 + 7, 360 assertions |
| 5. Créer `docs/ai-intel/baseline.md` | **FAIT** — ce document |
| 6. Proposer le plan de phase 1 | **FAIT** — `docs/ai-intel/phase1-plan.md` |
| 7. Arrêt et demande de revue | **FAIT** |

### Questions bloquantes

- **Q1** — Le catalogue stocke-t-il les `Rx` **verbatim** (recommandé, cf. R4) ou tente-t-il de les reconstruire depuis des littéraux ?
- **Q2** — Pulse entre-t-il dans le catalogue de la phase 1, ou reste-t-il codé en dur jusqu'à une phase ultérieure ?
- **Q3** — `telemetry.schema.json` est-il aligné sur le payload réel (13 clés), ou le payload doit-il changer ? *(Recommandation : aligner le schéma ; toute autre option modifie le comportement distribué.)*
- **Q4** — L'écart n° 4 de §5 (déchargement de ruche, local en retard sur hosted) est-il intentionnel ou une régression à corriger séparément ?
- **Q5** — `.gitattributes` : `*.ps1 text eol=crlf` (préserve l'arbre Windows actuel) ou `eol=lf` ? *(Recommandation : `eol=crlf` — les scripts ciblent Windows et sont téléchargés directement depuis `script.nep.red`.)*
- **Q6** — Le test de propriété de l'échappement (C3) tourne-t-il aussi sous `pwsh` Linux, ou reste-t-il cantonné à la CI Windows ?

**Aucune règle ni logique de suppression n'a été modifiée.**
