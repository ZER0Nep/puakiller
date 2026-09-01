# Preuve d'équivalence — migration du registre de règles vers `rules/catalog.json`

Date (UTC) : 2026-09-01
Base : commit `ff43b48e9622c422b7337198aa2730f1ce084bd9`
Portée : région de règles de `hosted-removal.ps1` et `PUAKILLER-LOCAL.ps1`

Point de revue humaine exigé avant que la région générée ne fasse autorité. Ce document rassemble ce qui a été **mesuré**, pas ce qui a été supposé.

---

## 1. Ce qui a changé, exactement

### 1.1 Écart de départ : 4 lignes, uniquement de l'alignement

Avant toute modification, la sortie du compilateur a été comparée à la région livrée :

```
région hosted-removal.ps1 : lignes 169-281, 114 lignes
110 lignes identiques au bit près
  4 lignes différentes
```

Les 4 lignes sont les entrées `OpenBook`, `ConvertMate`, `PDFEditor` et `OneStart`, qui portaient un alignement de colonnes ad hoc :

```powershell
-    @{ Name='OpenBook';    Label='OpenBook';    Rx='(?i)\bOpenBook\b';    Proc=@('OpenBook');    Pub='';    Nw=$true;  Harden=@(...) },
+    @{ Name='OpenBook'; Label='OpenBook'; Rx='(?i)\bOpenBook\b'; Proc=@('OpenBook'); Pub=''; Nw=$true; Harden=@(...) },
```

**Aucun caractère de valeur n'a changé.** Seuls des espaces de remplissage entre `;` et le nom de champ suivant ont été retirés. Les 7 autres entrées, dont les six regex complexes (`EPISoftware`, `OneBrowser`, `ManualFinder`, `KitchenCanvas`, `ShiftBrowser`, `ProOneStartHub`), étaient **déjà** identiques à la sortie du compilateur.

### 1.2 Second changement, délibéré : l'en-tête contributeur

L'en-tête disait encore d'éditer `$Puas` à la main. Le laisser aurait été une instruction fausse dans un fichier dont la région est désormais générée. Les 4 premières lignes ont été remplacées par 8 lignes pointant vers `rules/catalog.json` et `scripts/apply-generated.py`. **Commentaires uniquement, aucune ligne exécutable.**

### 1.3 Ce qui n'a pas changé

Les 4 divergences légitimes entre les deux scripts sont hors région et intactes :

| Divergence | Statut |
|---|---|
| `$NoElevate = $true` forcé dans `PUAKILLER-LOCAL.ps1` | intacte |
| `-Harden` activé par défaut en local, pas en hosted | intacte |
| `$StatsUrl` : `https://script.nep.red/stat` vs `''` | intacte |
| Déchargement de ruche : 6 tentatives vs 3 | intacte (question Q4, hors périmètre) |

Pulse (`$PulseRegex`, `$PulseGuids`, `$procNames`, `$genericExe`) reste codé en dur : hors périmètre de la phase 1 (question Q2).

---

## 2. Preuve n° 1 — sémantique de détection identique

Un instantané canonique de ce que le **moteur** voit a été pris avant la migration, par extraction AST (`SafeGetValue()`), sur les deux scripts : les 10 champs déclaratifs des 11 règles, les 10 signataires, et `$PulseRegex`.

```
docs/ai-intel/baseline-results/rules-golden.txt
26 lignes
sha256 = dfe4f76ce02e5ce7e713f2ad25297f431f192bd1e835d112519591b848f33aa1
```

Après migration, le même instantané a été recalculé :

```
sha256 = dfe4f76ce02e5ce7e713f2ad25297f431f192bd1e835d112519591b848f33aa1
identique : True
```

**Le moteur voit exactement les mêmes règles qu'avant.** C'est la propriété qui compte : la mise en forme du source n'a aucune incidence sur ce que `Invoke-PuaSweep`, `Test-PuaAliasDir` et `Invoke-CertSweep` reçoivent.

---

## 3. Preuve n° 2 — les tests existants, inchangés

| Test | Avant | Après | Note |
|---|---|---|---|
| `Test-PuaRules.ps1` | 322 | **320** | −2 : voir §5 |
| `Test-StatsUpdater.ps1` | PASS | PASS | |
| `Test-OneBrowserGuard.ps1` | PASS | PASS | |
| `Test-ShiftBrowserGuard.ps1` | PASS | PASS | |
| `Test-Logging.ps1` | 14 | 14 | |
| `Test-ExecutionContext.ps1` | 24 | 24 | |
| `Test-RuleCatalog.ps1` | — | **277** | nouveau |
| `tests/compiler/test_escape.py` | — | **13** | nouveau |
| parse-check | OK | OK | |
| lint anti-PS7 | OK | OK | |

Exécuté sur **Windows PowerShell 5.1 et PowerShell 7.6.5**. Aucun fichier d'or n'a été modifié pour faire passer un test.

---

## 4. Preuve n° 3 — le compilateur reproduit le compilateur en production

Le produit compilait déjà une regex de façon déterministe (`hosted-removal.ps1:281`) :

```powershell
$BadSignerRx = '(?i)(' + (($BadSigners | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
```

`tests/compiler/test_escape.py` compare la sortie de `scripts/lib/escape.py` à celle de `[regex]::Escape` **réellement exécuté**, sur les 10 signataires livrés et sur un corpus de littéraux hostiles (tous les métacaractères, séparateurs de chemin Windows, apostrophes, `$`, backtick, espaces). Résultat : **identique caractère pour caractère**.

Le test s'ignore proprement si aucun PowerShell n'est sur le `PATH`, pour rester exécutable sur le serveur Linux.

---

## 5. Le seul changement de comportement de test, assumé

`Test-PuaRules.ps1` passe de 322 à 320 assertions. Cause : `'OBS Studio'` figurait **deux fois** dans `$BENIGN_NAMES` (lignes 106 et 108). Le doublon a été retiré pour satisfaire `uniqueItems` dans `rules/schema/benign.schema.json`.

`'OBS Studio'` **reste dans le corpus** (ligne 106). Les deux assertions perdues sont la seconde vérification du même nom. Aucune protection n'est retirée.

---

## 6. Preuve n° 4 — la porte CI détecte réellement une édition manuelle

Test négatif exécuté : modification à la main de `Label='OpenBook'` en `Label='OpenBookX'` dans la région générée de `hosted-removal.ps1`.

```
python scripts/verify-generated.py   -> exit 1   (attendu 1)
restauration                          -> exit 0   (attendu 0)
```

`scripts/verify-generated.py` vérifie quatre propriétés :

```
== VALIDATION : 11 règles, 10 signataires acceptés
== SCHEMA     : catalog.json et benign.json conformes à leur JSON Schema
== IDEMPOTENCE: 11872 octets, stable entre deux exécutions
== SYNC       : hosted 169-285 et local 170-286 correspondent au catalogue
== PARITY     : régions identiques au bit près entre les deux scripts
```

---

## 7. Deux défauts réels trouvés en chemin

Les schémas n'étaient pas décoratifs — leur mise en service a immédiatement révélé :

1. **`provenance` aplati** — `ConvertTo-Json` transforme un tableau à un élément en scalaire. 50 champs du catalogue étaient concernés. Corrigé par `scripts/normalize-catalog.py`, documenté comme étape du flux de re-synchronisation.
2. **Doublon dans le corpus bénin** — voir §5.

Un troisième défaut, de mon fait, a été trouvé et corrigé : une tabulation littérale introduite dans `.github/workflows/tests.yml` rendait le YAML impossible à parser. Vérifié depuis avec `yaml.safe_load`.

---

## 8. Limite explicite de cette preuve

Elle établit que **les règles vues par le moteur sont inchangées** et que **la région générée est reproductible**. Elle n'établit pas que le comportement de remédiation à l'exécution est inchangé : aucun script de remédiation n'a été exécuté, par conception (`PLAN-IMPLEMENTATION.md`, phase 0). Cette garantie repose sur le fait que le code consommateur n'a pas été touché — vérifiable par `git diff`, qui ne montre aucune modification hors de la région de règles et de son en-tête.

---

## 9. Verdict

| Critère d'acceptation | Statut |
|---|---|
| Les deux scripts utilisent une source de vérité commune | **OK** — `rules/catalog.json` |
| Deux compilations successives sont byte-for-byte identiques | **OK** — 11872 octets stables |
| Tous les tests existants passent | **OK** — §3 et §5 |
| Compatibilité PowerShell 5.1 et 7 | **OK** — les deux moteurs, lint anti-PS7 vert |
| Toute différence fonctionnelle est explicitée et approuvée | **OK** — §1 et §5 ; en attente d'approbation |
| Aucune règle destructive auto-fusionnée | **OK** — rien n'a été commité ni poussé |

**Aucune règle de détection ni logique de suppression n'a été modifiée.** Le golden sémantique le prouve.
