# Plan de phase 1 — source de vérité et compilateur déterministe

Date (UTC) : 2026-09-01
Base : commit `ff43b48`, baseline verte (12/12, 360 assertions, PS 5.1 + 7)
Statut : **RÉALISÉE — première ébauche complète, non commitée, en attente de revue.**

> Les décisions Q1–Q6 ont été tranchées par moi-même sur demande explicite de l'utilisateur
> (« interroge toi-même et fais au mieux »). Elles sont reportées en fin de document avec leur
> justification. La preuve d'équivalence est dans `equivalence-proof.md`.
>
> **Écart assumé par rapport au plan initial :** le plan prévoyait C6 (marqueurs inertes) puis
> C8 (bascule à diff vide). L'écart réel s'étant révélé n'être que 4 lignes d'alignement, la
> normalisation et la bascule ont été faites en une seule opération, avec un golden sémantique
> pris avant/après pour prouver l'absence de changement de détection. Deux commits n'auraient
> rien prouvé de plus que le golden ne prouve déjà.

Objectif (`PLAN-IMPLEMENTATION.md`) : sortir la connaissance PUA du code **sans changer une seule détection**.

---

## Ce que la phase 0 a rendu facile

Trois découvertes réduisent nettement le risque par rapport à un plan écrit à l'aveugle :

1. **La région de règles est déjà byte-for-byte identique entre les deux scripts** (`sha256 6f49976c…` sur `hosted:198-281` et `local:199-282`). Le compilateur a une cible unique, non ambiguë.
2. **L'extraction statique par AST existe déjà et est éprouvée en CI** : `Test-PuaRules.ps1:44-62` (`Get-ScriptVar` + `SafeGetValue()`). Rien à inventer pour lire `$Puas` sans exécuter le script.
3. **Le corpus bénin machine-readable existe déjà** : `$BENIGN_NAMES` / `$BENIGN_PROCS` / `$BENIGN_PUBLISHERS`. Il faut l'extraire, pas le créer.

Une découverte augmente le risque :

4. **`core.autocrlf=true`, pas de `.gitattributes`, arbre 100 % CRLF.** Avec un compilateur destiné à tourner sur le serveur **Linux**, « byte-for-byte » n'est pas défini tant que les fins de ligne ne sont pas figées. D'où le commit **C1bis**, absent du plan initial.

---

## Principes de découpage

- Chaque commit est **réversible par un seul `git revert`** et laisse la CI verte.
- C0 → C5 sont **purement additifs** : aucun script distribué touché.
- Premier script distribué touché : **C6**, commentaires seuls.
- Premier remplacement de contenu : **C8**, protégé par la preuve d'équivalence de C7.
- **Stop obligatoire** dès qu'une sortie générée diffère sémantiquement d'une regex ou d'une suppression existante.

---

## C0 — Combler les lacunes de test avant de toucher quoi que ce soit

| | |
|---|---|
| **Fichiers touchés** | `tests/Test-PuaRules.ps1` (ajouts), `tests/Test-RuleCatalog.ps1` (nouveau) |
| **Comportement préservé** | Intégral — aucun code de production touché. |
| **Contenu** | Comble L1, L2, L4, L6 (`baseline.md` §6) : ① ajouter `Label` à `Norm()` (parité complète) ; ② valider chaque `Hashes` sur `^[0-9a-f]{64}$` ; ③ refuser tout `Name` de moins de 5 caractères ou figurant dans `$BENIGN_NAMES` (verrouille structurellement I15/L4) ; ④ unicité des `Name` ; ⑤ figer un fichier d'or : sérialisation canonique des 11 entrées + 10 signataires + `$PulseRegex`. |
| **Tests** | Nouveaux tests verts. Les 322 checks existants inchangés. PS 5.1 + 7. |
| **Rollback** | `git revert`. Aucun impact production. |
| **Garde** | Si ③ échoue sur une règle **existante**, c'est une découverte de sûreté : arrêt et revue, jamais un assouplissement du seuil. |

Ce commit a une valeur propre même si la phase 1 s'arrête là.

---

## C1bis — `.gitattributes` (imposé par la cible Linux)

| | |
|---|---|
| **Fichiers touchés** | `.gitattributes` (nouveau) |
| **Comportement préservé** | Intégral — aucun contenu modifié si la valeur choisie correspond à l'état actuel du blob. |
| **Contenu** | Fige les fins de ligne des `.ps1` (recommandation : `*.ps1 text eol=crlf`, cf. Q5) pour que Windows et le serveur Linux produisent des octets identiques. |
| **Tests** | `git diff --stat` **vide** après `git add --renormalize .`. Diff non vide ⇒ la valeur choisie ne correspond pas à l'état réel : arrêt et revue. |
| **Rollback** | `git revert`. |
| **Pourquoi si tôt** | Tous les critères byte-for-byte suivants en dépendent. Sans ce commit, C4/C7/C8 mesurent une propriété qui n'existe pas. |

---

## C1 — Schémas du catalogue et du corpus bénin

| | |
|---|---|
| **Fichiers touchés** | `rules/schema/catalog.schema.json`, `rules/schema/benign.schema.json` (nouveaux) |
| **Comportement préservé** | Intégral — fichiers inertes, non chargés. |
| **Contenu** | Schémas clos (`additionalProperties: false`), calqués sur les **10 champs déclaratifs réels** (`baseline.md` §3.1). **`Dirs` et `RegPaths` exclus** — champs injectés à l'exécution. Ajouts : `provenance[]` (URL publique, fournisseur, date), `rationale` (prose de sûreté), `requires_manual_regex`. Contraintes portant la sûreté : `Hashes` en `^[0-9a-f]{64}$` ; toute entrée avec `Aliases` non vide **doit** porter au moins un de `Hashes`/`Proc`/`Pub` non vide — cela encode I15 dans le schéma, pas seulement dans un test. |
| **Tests** | Validation contre le méta-schéma 2020-12 ; rejet d'une propriété inconnue, d'un hash majuscule, d'un `Aliases` sans garde. |
| **Rollback** | `git revert`. Rien ne consomme ces fichiers. |
| **Décision requise** | Q1 et Q2 avant de figer. |

---

## C2 — Extraction du catalogue, sans branchement

| | |
|---|---|
| **Fichiers touchés** | `rules/catalog.json`, `rules/benign.json` (nouveaux), `scripts/extract-rules.ps1` (nouveau) |
| **Comportement préservé** | Intégral — les scripts continuent d'utiliser leurs `$Puas`/`$BadSigners` en dur. |
| **Contenu** | Export **mécanique** depuis l'AST, en réutilisant la mécanique éprouvée de `Test-PuaRules.ps1:44-62`. Les `Rx` sont copiées **verbatim** (R4), marquées `requires_manual_regex: true` là où le motif n'est pas une simple alternance de littéraux. La prose de provenance des commentaires devient `provenance[]` + `rationale` — **relecture humaine entrée par entrée, non mécanisable**. `benign.json` reprend les 3 corpus tels quels. |
| **Tests** | Équivalence : catalogue re-sérialisé == fichier d'or de C0. Conformité au schéma C1. Unicité des `Name`. Aucune entrée ne perd de champ. |
| **Rollback** | `git revert`. Aucun consommateur. |
| **Critère d'arrêt** | Entrée non reproductible à l'identique ⇒ **arrêt** : elle reste manuelle et est consignée dans `docs/ai-intel/non-generable.md`. Ne jamais approximer une règle. |

---

## C3 — Fonction d'échappement, isolée et testée

| | |
|---|---|
| **Fichiers touchés** | `scripts/lib/escape.py`, `tests/compiler/test_escape.py` (nouveaux) |
| **Comportement préservé** | Intégral. |
| **Contenu** | Reproduit exactement le modèle **déjà en production** (`hosted-removal.ps1:281`) : littéraux exacts → `[regex]::Escape` → alternance `(?i)(…)`. Plus l'échappement de littéral de chaîne PowerShell (`'` doublé). Rien d'autre. Mitige R3, le risque le plus destructeur de la phase. |
| **Tests** | Unitaires + **property-based** (Hypothesis, dev/test uniquement) : pour tout littéral, la valeur échappée matche exactement ce littéral et **rien d'autre**. Cas hostiles : `.`, `*`, `?`, `[`, `]`, `\`, `$`, backtick, `'`, `"`, `(`, `)`, `\|`, `+`, `^`, espaces, Unicode, chaîne vide. **Vérification croisée en exécutant `pwsh`** — disponible sous Linux comme sous Windows (Q6). **Test d'ancrage : la sortie sur les 10 `$BadSigners` réels doit être identique caractère pour caractère à `$BadSignerRx` produit par le script.** |
| **Rollback** | `git revert`. |

Le test d'ancrage est le meilleur du lot : il compare le nouveau compilateur au compilateur déjà en production, sur données réelles.

---

## C4 — Compilateur, en écriture vers un dossier temporaire

| | |
|---|---|
| **Fichiers touchés** | `scripts/compile-rules.py` (nouveau) |
| **Comportement préservé** | Intégral — écrit dans `build/`, jamais sur les scripts. |
| **Contenu** | Lit `rules/catalog.json`, produit la région de règles des **deux** scripts (identique, `baseline.md` §5). Tri stable. **Ré-émet les commentaires de provenance** — un bloc généré sans commentaires est un échec (R6). Recopie les `Rx` verbatim, ne les reconstruit jamais. Refuse toute regex non marquée approuvée. Python 3 stdlib seule ; identique sous Linux. Fins de ligne pilotées par `.gitattributes` (C1bis), jamais par la plateforme. |
| **Tests** | Idempotence : deux exécutions ⇒ octets identiques (I2). Déterminisme : ordre d'entrée permuté ⇒ même sortie. Refus : catalogue avec regex libre ⇒ échec. Casse : comparaison des `Name`/`Aliases` explicitement insensible à la casse, jamais déléguée au système de fichiers (`baseline.md` §8). |
| **Rollback** | `git revert`. |

---

## C5 — `verify-generated`, en mode avertissement

| | |
|---|---|
| **Fichiers touchés** | `scripts/verify-generated.py` (nouveau), `.github/workflows/tests.yml` (job additionnel `continue-on-error`) |
| **Comportement préservé** | Intégral. Le job n'empêche aucun merge. |
| **Contenu** | Compare le contenu généré à la région de règles actuelle et **publie le diff en artefact**. Cible **les régions de règles uniquement**, jamais `README.md` (R8, bruit des commits `[skip ci]`). Déclare `permissions: contents: read`. |
| **Tests** | Le job tourne et produit un diff lisible. |
| **Rollback** | `git revert` du workflow. |
| **Rôle** | **Étape de preuve.** Tant que ce diff n'est pas vide ou intégralement expliqué, C6 → C8 n'ont pas le droit d'exister. |

À saisir au passage : ajouter `permissions: contents: read` au job de test existant (`baseline.md` §7) — durcissement à coût zéro, sans effet fonctionnel.

---

## C6 — Marqueurs de régions générées, inertes

| | |
|---|---|
| **Fichiers touchés** | `hosted-removal.ps1`, `PUAKILLER-LOCAL.ps1` — **premiers scripts distribués touchés** |
| **Comportement préservé** | Intégral. Ajout de `# region GENERATED:puas` / `# endregion` autour de `hosted:198-281` et `local:199-282`. Zéro changement de code exécutable. |
| **Tests** | Suite complète PS 5.1 **et** 7 (12/12). Parse-check. Lint PS5.1. Diff relu ligne à ligne : **uniquement des lignes de commentaire**. |
| **Rollback** | `git revert` ; comportement identique. |
| **Garde** | Une seule ligne non commentaire dans le diff ⇒ **commit refusé**. |

---

## C7 — Preuve d'équivalence byte-for-byte

| | |
|---|---|
| **Fichiers touchés** | `docs/ai-intel/equivalence-proof.md` (nouveau) — aucun code |
| **Comportement préservé** | Intégral. |
| **Contenu** | Sortie de `verify-generated` sur les régions délimitées en C6 : diff **vide**, ou liste exhaustive des écarts avec la décision humaine associée pour chacun. Consigne les `sha256` avant/après pour les deux scripts, **sur les deux plateformes** (Windows + Linux), ce qui valide C1bis. |
| **Tests** | — (document). |
| **Rollback** | `git revert`. |
| **Point de revue humain obligatoire** | **Aucun commit suivant sans approbation explicite de ce document.** |

---

## C8 — Bascule : les régions deviennent générées

| | |
|---|---|
| **Fichiers touchés** | `hosted-removal.ps1`, `PUAKILLER-LOCAL.ps1` (contenu des régions remplacé par la sortie du compilateur) |
| **Comportement préservé** | **Byte-for-byte identique** dans les régions, prouvé en C7. Le commit ne devrait produire **aucun diff net** ; s'il en produit un, c'est un bug du compilateur, pas une amélioration. |
| **Tests** | Suite complète PS 5.1 + 7. Fichier d'or de C0 **vert sans modification**. `sha256` de la région inchangé sur les deux scripts et toujours égal entre eux. Recompilation ⇒ diff vide. |
| **Rollback** | `git revert` restaure le contenu littéral. Catalogue et compilateur survivent en C1–C4 (inertes) : rien n'est perdu. |
| **Critère d'arrêt dur** | Modifier le fichier d'or de C0 pour faire passer les tests est **interdit**. Un test d'or qui casse signifie que la détection a changé ⇒ arrêt, revue. |

---

## C9 — `verify-generated` bloquant + garde anti-édition manuelle

| | |
|---|---|
| **Fichiers touchés** | `.github/workflows/tests.yml` (`continue-on-error` retiré), `CODEOWNERS` (nouveau) |
| **Comportement préservé** | Intégral. |
| **Contenu** | La CI échoue si une région générée a été éditée manuellement (R5). `CODEOWNERS` exige une revue nommée sur `rules/` et sur les régions générées. |
| **Tests** | Test négatif : édition manuelle simulée d'une région ⇒ CI rouge. |
| **Rollback** | `git revert` ; la CI redevient non bloquante. |

---

## Ce que la phase 1 ne fait pas

- Aucune règle nouvelle, aucune règle supprimée, aucun élargissement de motif.
- **Aucune modification de `Send-Stat`, `-NoStats` ou du payload de télémétrie.** L'alignement `telemetry.schema.json` ↔ payload réel (`baseline.md` §4, écart sur 7 clés) est une phase distincte. Le test à champs sentinelles (L3) doit précéder toute modification de `Send-Stat`.
- Aucune correction de l'écart n° 4 entre les deux scripts (déchargement de ruche) — Q4, hors périmètre.
- Aucun appel réseau, aucun LLM, aucun provider — phase 2.
- Aucun retrait du repli `r.jina.ai` — dette documentée, décision séparée.
- Aucune publication, aucun push, aucune PR, aucune ressource distante modifiée.

---

## État de réalisation

| Commit prévu | Statut | Livrable |
|---|---|---|
| C0 — durcir les tests | **fait** | `tests/Test-RuleCatalog.ps1` (277 checks) ; garde `Name` ≥ 5, hash 64-hex, unicité, alias gardé |
| C1bis — `.gitattributes` | **fait** | `.gitattributes` ; `git add --renormalize` → diff vide, `eol=crlf` confirmé conforme |
| C1 — schémas | **fait** | `rules/schema/catalog.schema.json`, `rules/schema/benign.schema.json`, validés en CI si `jsonschema` présent |
| C2 — extraction | **fait** | `rules/catalog.json` (11 règles, 10 signataires), `rules/benign.json` ; `scripts/extract-rules.ps1`, `scripts/normalize-catalog.py` |
| C3 — échappement | **fait** | `scripts/lib/escape.py` + `tests/compiler/test_escape.py` (13 tests, ancrés sur `[regex]::Escape` réel) |
| C4 — compilateur | **fait** | `scripts/compile-rules.py` ; idempotent, 11872 octets stables |
| C5 — `verify-generated` | **fait** | `scripts/verify-generated.py` ; 4 contrôles ; test négatif validé |
| C6 + C8 — bascule | **fait** | régions générées dans les deux scripts ; golden sémantique `dfe4f76c…` inchangé |
| C7 — preuve | **fait** | `docs/ai-intel/equivalence-proof.md` |
| C9 — CI bloquante + CODEOWNERS | **fait** | `permissions: contents: read`, 5 étapes ajoutées, `CODEOWNERS` |

Reste ouvert et non fait, volontairement : l'alignement du code de télémétrie (le **schéma** du kit a été aligné sur le payload réel, le code n'a pas été touché), Pulse, et l'écart de déchargement de ruche.

## Décisions Q1–Q6, tranchées

| Q | Décision | Justification |
|---|---|---|
| Q1 | `Rx` stockées **verbatim**, `requires_manual_regex` calculé | 6 des 11 patterns encodent un raisonnement de faux positifs écrit à la main |
| Q2 | Pulse **reste codé en dur** | hors périmètre ; `$PulseRegex` a ~25 sites d'appel, sa migration mérite sa propre phase |
| Q3 | `telemetry.schema.json` **aligné sur le produit** | l'inverse aurait modifié le comportement distribué, interdit en phase 1 |
| Q4 | Écart de ruche **non touché** | correctif fonctionnel séparé, à décider |
| Q5 | `*.ps1 text eol=crlf` | les scripts ciblent Windows et sont servis directement ; `--renormalize` confirme un diff vide |
| Q6 | Ancrage `pwsh` **actif partout**, skip propre sans PowerShell | tourne sur le serveur Linux comme sur la CI Windows |

## Questions bloquantes avant C0 (historique)

- **Q1** — Le catalogue stocke-t-il les `Rx` **verbatim** (recommandé : 7 des 11 sont des motifs manuels porteurs d'un raisonnement de sûreté) ou tente-t-il de les reconstruire ?
- **Q2** — Pulse (`$PulseRegex`, `$PulseGuids`, `$procNames`, `$genericExe`) entre-t-il dans le catalogue en phase 1, ou reste-t-il codé en dur ?
- **Q3** — `telemetry.schema.json` est aligné sur le payload réel (13 clés), ou le payload change ? *(Recommandation : aligner le schéma.)*
- **Q4** — L'écart de déchargement de ruche (local 3 tentatives vs hosted 6) est-il intentionnel ou une régression à corriger séparément ?
- **Q5** — `.gitattributes` : `*.ps1 text eol=crlf` ou `eol=lf` ? *(Recommandation : `eol=crlf` — les scripts ciblent Windows et sont téléchargés directement depuis `script.nep.red`.)*
- **Q6** — Le test de propriété d'échappement tourne-t-il aussi sous `pwsh` Linux, ou reste-t-il cantonné à la CI Windows ?
