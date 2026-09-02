# Phase 5 — publication

Ce document dit ce que fait la phase 5, et surtout **ce qu'elle a délibérément refusé de
faire**. Le reste se lit dans le code.

---

## Ce qui a été construit

| Composant | Rôle |
|---|---|
| `intel-factory/src/puakiller_intel/bundle.py` | La frontière, en données : un enregistrement fermé de 17 clés, construit d'un côté, revalidé intégralement de l'autre. |
| `intel-factory/src/puakiller_intel/github.py` | Le seul client capable d'écrire. Cinq appels, `GET`/`POST` uniquement, `api.github.com` uniquement. |
| `intel-factory/src/puakiller_intel/publish.py` | Exécute le verdict du validateur. Rend l'Issue ou la Draft PR, écrit la proposition. |
| `scripts/verify-proposals.py` | La porte CI sur `rules/proposed/`. Ce sont les « nouveaux tests » que le mandat exige de la PR. |
| `scripts/promote-proposal.py` | L'étape humaine. Refuse tant que `Name` et `Rx` ne sont pas écrits à la main. |
| `.github/workflows/intel-propose.yml` | Deux jobs, deux jeux de secrets disjoints. |
| `intel-factory/tests/test_publish.py` | 60 tests, tous hors ligne. |

---

## Les trois décisions à contester

### 1. Une Draft PR ne touche pas `rules/catalog.json`

Elle ajoute **un seul fichier**, `rules/proposed/<id>.json`, et rien d'autre.

Modifier le catalogue ferait régénérer la région de règles des deux scripts distribués : le
diff de la PR contiendrait alors une modification de `hosted-removal.ps1`, le script qui
supprime des dossiers sur les machines des utilisateurs. Une pull request ouverte par une
machine, dont le diff touche ce script, est à un clic distrait de « Ready for review » puis de
la fusion.

Le fichier de proposition est **inerte** : aucun compilateur ne le lit, aucun test n'en dérive
de règle, et fusionner la PR telle quelle ne change strictement aucun comportement de
détection.

**Ce que ça coûte :** le mainteneur fait deux étapes au lieu d'une, et il relit un JSON qui
n'est pas exactement le diff qu'il finira par appliquer. C'est un vrai coût ergonomique, et
c'est l'objection principale à cette décision.

### 2. Un indicateur `folder` devient un `Alias`, jamais un `Name`

Ce n'est pas un détail de nommage. Dans le catalogue :

- `Name` déclenche un balayage **inconditionnel** de LOCALAPPDATA, APPDATA, Programs, Start
  Menu, ProgramFiles(x86) et ProgramData ;
- un `Alias` n'est supprimé que si une preuve statique — hash enregistré, nom de fichier
  correspondant, signataire — est trouvée **dans** le dossier.

L'usine ne remplit donc jamais `Name`, et `Rx` reste `null` avec lui. Le mainteneur qui promeut
une proposition doit écrire les deux à la main. C'est exactement le moment où la décision
destructrice doit être prise par une personne.

### 3. Le publieur n'a pas le droit de reconsidérer

`publish.py` n'attribue aucun score et ne recalcule aucune route. Le verdict vient de
`validate.py`, déterministe et hors ligne. Un publieur capable de contredire le validateur
rendrait le validateur décoratif.

---

## La séparation collecte / publication

```
job evaluate                            job publish
permissions: {}                         permissions: contents/issues/pull-requests: write
HYBRID_ANALYSIS_API_KEY   ──┐            (aucun secret fournisseur)
LLM_API_KEY               ──┤            GITHUB_TOKEN
                            │
                            └──> bundle.json ──> artefact ──> lecture ──> Issue / Draft PR
```

Trois choses rendent cette séparation vérifiable plutôt que promise :

1. **`permissions: {}` sur le job d'évaluation.** Il ne pourrait pas ouvrir une PR même si son
   code le voulait.
2. **Aucun secret fournisseur dans le job de publication.** Une étape CI extrait le bloc
   `publish:` du workflow et échoue s'il mentionne `HYBRID_ANALYSIS`, `TRIAGE`, `LLM_API_KEY`,
   `ANTHROPIC` ou `OPENAI`. Testé négativement : injecter la clé fait bien échouer l'étape.
3. **`publish.py`, `bundle.py` et `github.py` n'importent aucun module porteur de clé.**
   Assertion sur l'AST, pas sur une convention : `config`, `transport`, `providers`,
   `hybrid_analysis`, `llm` et `pipeline` sont interdits d'import dans les trois.

Le bundle est le seul objet qui traverse. Il n'a **aucun champ** capable de porter une page, un
corps de réponse, un chemin de cache ou une clé — et une clé inconnue est **refusée**, pas
ignorée : un `raw_report` ajouté par une évolution future casse le publieur au lieu de publier
silencieusement un rapport de bac à sable dans une Issue publique.

---

## Ce que le publieur ne peut pas faire

| Interdit | Comment c'est empêché |
|---|---|
| Fusionner | `_request` refuse toute méthode hors `GET`/`POST`. Aucun endpoint de merge n'existe. Assertion sur l'AST, pas sur le texte. |
| Ouvrir une PR non-draft | `draft: True` est un littéral, pas un paramètre. `inspect.signature` le vérifie. |
| Écrire un fichier via l'API | Aucun appel Contents. Les fichiers passent par git, sous la même revue que n'importe quel commit. |
| Joindre un autre hôte | `api.github.com` en dur, vérifié à chaque requête. Aucun autre hôte n'apparaît dans le module. |
| Fuiter le jeton | Il n'est stocké nulle part : lu dans l'environnement au moment de construire l'en-tête. Un `repr` de l'objet ne peut pas le contenir. |
| Publier un candidat rejeté | `route: "reject"` n'a pas de bundle. Le validateur ne l'écrit pas, et le publieur le refuserait. |

---

## Injection de prompt et Markdown hostile

Les valeurs d'indicateurs viennent de rapports publics, donc d'entrées hostiles par hypothèse.
Elles finissent dans un corps Markdown public. `md_cell` neutralise ce qui casserait la mise en
page ou impersonnerait le rapport : caractères de contrôle, retours à la ligne, `|`, backticks.

La valeur qui fait foi reste dans le fichier JSON joint. Le corps est la copie de lecture.

---

## Idempotence

Relancer le workflow sur la même famille n'ouvre pas un second élément :

- pour une Issue, le titre exact est cherché parmi les Issues ouvertes portant `ai-intel` ;
- pour une Draft PR, la branche `intel/proposal/<id>` est cherchée parmi les PR ouvertes.

Le plan devient `skip`, et `execute` n'envoie rien.

---

## Labels

| Label | Quand |
|---|---|
| `ai-intel` | Toujours. Permet de filtrer tout ce que l'usine a ouvert. |
| `needs-human-review` | Toujours. |
| `no-auto-merge` | Toujours. La règle est lisible sur l'élément, pas seulement dans un document. |
| `intel:triage` / `intel:proposal` | Selon la route. |
| `needs-manual-regex` | `requires_manual_regex` est vrai. |
| `benign-collision` | Le critic a trouvé une collision bénigne. |
| `destructive-risk` | Au moins un indicateur est classé `high`. |

---

## Comment vérifier tout ça localement

```bash
# 60 tests de la frontière de publication, hors ligne
python3 intel-factory/tests/test_publish.py

# La porte CI sur les propositions
python3 scripts/verify-proposals.py

# De bout en bout, sans clé et sans réseau
cd intel-factory
PYTHONPATH=src python3 -m puakiller_intel run --family OneStart --seed onestart --out ../out
PYTHONPATH=src python3 -m puakiller_intel publish \
    --bundle ../out/bundle.json --repo ZER0Nep/puakiller --root ..
```

La commande `publish` **ne publie rien** sans `--execute`. Une commande qui publie par défaut
publie par accident.
