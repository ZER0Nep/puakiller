# État du chantier IA — phases 0 à 7 (toutes terminées)

Dernière mise à jour (UTC) : 2026-09-02
Base : `ff43b48` (`main`)

Ce document existe pour qu'une reprise à froid n'ait pas à reconstituer le contexte depuis les
diffs. Il dit où en est le travail, ce qui bloque, et quelles décisions ont été prises et
pourquoi — ces dernières seules ne se déduisent pas du code.

---

## Où en est le travail

| Phase | Sujet | État | PR |
|---|---|---|---|
| 0 | Inventaire et baseline | terminée | — (`docs/ai-intel/baseline.md`) |
| 1 | Catalogue + compilateur déterministe | terminée | [#1](https://github.com/ZER0Nep/puakiller/pull/1) |
| 2 | Intel Factory hors ligne | terminée | [#2](https://github.com/ZER0Nep/puakiller/pull/2) |
| 3 | Hybrid Analysis lecture seule | terminée | [#3](https://github.com/ZER0Nep/puakiller/pull/3) |
| 4 | Rôles LLM scout / critic | terminée | [#4](https://github.com/ZER0Nep/puakiller/pull/4) |
| 5 | Publication Issue / Draft PR | terminée | [#5](https://github.com/ZER0Nep/puakiller/pull/5) |
| 6 | Serveur distant (Linux) | terminée | [#6](https://github.com/ZER0Nep/puakiller/pull/6) |
| 7 | Triage optionnel | terminée | [#7](https://github.com/ZER0Nep/puakiller/pull/7) |

Les quatre branches sont **empilées** et doivent être relues dans l'ordre :

```
feat/rule-catalog-compiler          -> #1
  feat/intel-factory-offline        -> #2
    feat/hybrid-analysis-readonly   -> #3
      feat/llm-scout-critic         -> #4
        feat/publish-proposals      -> #5
          feat/deploy-scheduled-factory -> #6
            feat/optional-triage      -> #7
```

## Ce qui bloque

**La CI n'a jamais tourné sur ces PR.** Elles viennent d'un fork (`iPresing/puakiller`), et
GitHub exige qu'un mainteneur autorise l'exécution des workflows pour la première contribution
d'un compte depuis un fork. Un clic de `@ZER0Nep` sur « Approve and run workflows » suffit.

Tout a donc été vérifié **localement**, y compris depuis un clone neuf de la branche :

- 7 suites PowerShell × 2 moteurs (Windows PowerShell 5.1 et PowerShell 7.6.5)
- `scripts/verify-generated.py` — 5 contrôles ; `scripts/verify-proposals.py` — porte propositions
- 250 tests Python, tous hors ligne

**L'accès API Hybrid Analysis n'est pas encore accordé.** Une demande de vetting est en attente ;
une relance est prête dans `~/Downloads/hybrid-analysis-vetting-email.txt`. Cela ne bloque pas le
développement : la phase 3 est écrite et testée sur cassettes enregistrées, et le vetting ne
débloque que le mode `collect` réel.

---

## Décisions structurantes, et leur raison

Celles-ci ne se déduisent pas du code. Les contredire est légitime ; les défaire par accident ne
l'est pas.

### Phase 1

- **Les `Rx` sont stockées verbatim, jamais reconstruites.** Six des onze motifs encodent un
  raisonnement de faux positifs écrit à la main.
- **Pulse reste codé en dur.** `$PulseRegex` a ~25 sites d'appel ; sa migration mérite sa propre
  phase.
- **`telemetry.schema.json` a été aligné sur le produit**, pas l'inverse : aligner le produit sur
  le schéma aurait modifié le comportement distribué.
- **`.gitattributes` fige `*.ps1` en CRLF.** Sans lui, « byte-for-byte » n'est pas défini entre le
  poste Windows et le serveur Linux.

### Phase 2

- **Un constat bloquant retire l'indicateur fautif, pas tout le candidat.** La première version
  rejetait une famille notée 100/100 parce qu'un de ses neuf indicateurs avait une source unique.
  C'est le mauvais incitatif : ça pousse à assouplir le critic.
- **L'evidence accepte les SHA-256 en majuscules**, que les rapports publics publient ainsi. Seul
  l'indicateur — ce qui devient une règle — doit être canonique.

### Phase 3

- **Seuls des endpoints GET sont utilisés.** La recherche plein texte de Hybrid Analysis est en
  `POST /search/terms` ; la supporter donnerait au transport la capacité d'envoyer un corps, et un
  transport qui peut envoyer un corps peut uploader un fichier. **C'est l'arbitrage le plus
  contestable de tout le chantier** : il coûte la découverte par nom de famille via ce provider.
  Les seeds sont donc des SHA-256 et des identifiants de rapport publics.
- **`collect` refuse de démarrer sans clé** plutôt que de renvoyer un ensemble vide : un
  collecteur vide est indiscernable d'un collecteur qui n'a rien trouvé.

### Phase 4

- **Le critic a deux couches.** Le déterministe possède toute objection **bloquante** ; le modèle
  est **advisory seulement**. Une objection qu'on ne peut ni inspecter ni tester serait aussi peu
  responsable qu'un indicateur qu'on ne peut pas sourcer.
- **L'API modèle a son propre client POST.** `transport.py` reste GET-only.
- **La politique sortante a un axe `llm_host`**, distinct du mode : le Job B peut parler à un
  modèle, le Job C non, et les deux surviennent dans un même run `evaluate`.

### Phase 7

- **Triage corrobore, il n'origine pas.** L'allowlist de champs fait deux entrées : SHA-256 et
  nom de fichier soumis. Signatures, configurations extraites, fichiers déposés et lignes de
  commande ne sont pas lus. La valeur d'une seconde source est de renforcer la corroboration
  d'indicateurs qui existent déjà (+25 au score) ; laisser un fournisseur optionnel introduire
  un type d'indicateur inédit mettrait le maillon le plus faible au plus près de la règle.
- **Deux interrupteurs, et il faut les deux.** `--triage` **et** `TRIAGE_ENABLED`. L'un sans
  l'autre est un refus explicite : un fournisseur optionnel qui s'active tout seul n'est pas
  optionnel. Construire un `TriageProvider` désactivé lève une erreur.
- **La recherche de Triage est un `GET`.** C'est ce qui rend le semis par nom de famille
  possible ici alors que la phase 3 y a renoncé côté Hybrid Analysis (`POST /search/terms`).
  C'est le meilleur argument pour activer Triage, et la raison d'être de l'option.
- **Un troisième site `.reveal()`.** L'invariant 5 passe d'un *compte* à une *liste nommée* :
  `hybrid_analysis.py`, `llm.py`, `triage.py`. La propriété qui compte est quels modules posent
  une clé sur le fil, pas combien.
- **La panne d'une source optionnelle ne fait pas échouer le run** ; la panne de la source
  requise, si. Elle est signalée sur stderr, jamais avalée.

### Phase 6

- **Le serveur ne publie pas.** Il collecte et évalue ; l'Issue ou la Draft PR vient de GitHub
  Actions ou du poste d'un opérateur. La machine qui détient les clés fournisseur ne détient
  jamais de droit d'écriture sur le dépôt — la séparation de la phase 5, étendue au matériel.
- **Pas de `healthcheck:` compose.** Ces conteneurs sont des jobs batch : ils démarrent,
  écrivent, sortent. Un healthcheck sur un conteneur qui sort par conception ne dit rien. Ce qui
  peut réellement casser, c'est que **les cycles cessent** — et ça ne produit ni erreur ni ligne
  de log, juste du silence. `puakiller-intel health` lit donc l'enregistrement du dernier run.
- **Sortie 1 d'un cycle n'est pas une panne.** C'est un candidat refusé, le résultat normal.
  `SuccessExitStatus=0 1` dans l'unité systemd le dit, sinon on apprend à ignorer une unité rouge.
- **Un tick qui trouve le verrou pris saute, il ne fait pas la queue.** Faire la queue derrière
  un run lent transforme un run lent en backlog. Verrou périmé après 1 h, repris, et la reprise
  est signalée : un verrou volé veut dire qu'un run est mort sans nettoyer.
- **Les prompts sont montés, pas embarqués dans l'image.** Défaut réel corrigé au passage :
  installé en `site-packages`, `PROMPTS_DIR` ne trouvait rien et `PromptLibrary` estampillait
  `+missing` — une provenance qui dit « prompt inconnu » n'est pas reproductible.

### Phase 5

- **Une Draft PR n'édite pas `rules/catalog.json`.** Elle ajoute un seul fichier inerte sous
  `rules/proposed/`. Toucher au catalogue ferait régénérer la région de règles des deux scripts
  distribués, et une PR ouverte par une machine dont le diff modifie `hosted-removal.ps1` est à
  un clic de la fusion. **Coût assumé :** le mainteneur relit un JSON, pas le diff final.
  Détaillé dans `phase5-publication.md`.
- **Un indicateur `folder` devient un `Alias`, jamais un `Name`.** `Name` déclenche un balayage
  inconditionnel ; un alias exige une preuve statique dans le dossier. `Name` et `Rx` restent
  `null` : `promote-proposal.py` refuse tant qu'une personne ne les a pas écrits.
- **Le client GitHub ne connaît que `GET` et `POST`.** Pas d'endpoint de merge, pas d'API
  Contents, `draft: True` en littéral. « Aucune fusion automatique » devient un appel
  impossible plutôt qu'une politique à respecter.
- **Le jeton n'est stocké nulle part** : lu dans l'environnement au moment de construire
  l'en-tête. Ça évite un troisième site `.reveal()` et rend l'invariant 5 encore vrai.

---

## Invariants qu'aucune phase suivante ne doit défaire

1. Aucune règle de suppression n'est auto-fusionnée. Les PR restent en **draft**.
2. Aucun échantillon ne peut être soumis. `transport.py` reste sans corps de requête.
3. Aucune donnée SOC n'entre. Le filtre échoue fermé et nomme la classe, jamais la valeur.
4. Aucun modèle ne peut bloquer ni approuver.
5. `.reveal()` n'existe qu'aux trois sites nommés dans `REVEAL_SITES` — `hybrid_analysis.py`,
   `llm.py`, `triage.py`. Un quatrième fait échouer un test.
6. Le mode par défaut (`fixture`) ne joint aucun hôte, et la CI ne peut faire aucun appel payant.
7. La sémantique de détection est figée par le golden
   `docs/ai-intel/baseline-results/rules-golden.txt` (`sha256 dfe4f76c…`).
8. Le job qui publie ne voit aucun secret fournisseur. Une étape CI lit le bloc `publish:` du
   workflow et échoue s'il mentionne `HYBRID_ANALYSIS`, `TRIAGE`, `LLM_API_KEY`, `ANTHROPIC`
   ou `OPENAI`.
9. `publish.py`, `bundle.py` et `github.py` n'importent ni `config`, ni `transport`, ni
   `providers`, ni `hybrid_analysis`, ni `llm`, ni `pipeline`. Vérifié sur l'AST.
10. Le bundle est un schéma fermé. Une clé inconnue est refusée, jamais ignorée.
11. Le conteneur par défaut a `network_mode: none`. Le service en ligne est derrière un profil
    compose et ne peut pas démarrer par accident.
12. Aucun `GITHUB_TOKEN` sur l'hôte de collecte. Vérifié par un test sur `compose.yaml` et
    `.env.example`.
13. `last-run.json` et `run.lock` ont un jeu de clés fermé et ne portent ni hostname, ni
    username, ni preuve.
14. Triage reste optionnel. Aucun mode ne joint `tria.ge` sans `--triage` **et**
    `TRIAGE_ENABLED`, et seul le mode `collect` peut l'atteindre même activé.
15. L'allowlist Triage fait deux types (`sha256`, `filename`). L'élargir est un changement de
    conception, pas un ajustement.

---

## Pour reprendre

```bash
# Tout est-il encore vert ?
python3 scripts/verify-generated.py
python3 tests/compiler/test_escape.py
python3 scripts/verify-proposals.py
for t in test_intel_factory test_hybrid_analysis test_llm_roles test_publish test_deploy test_triage; do
    python3 intel-factory/tests/$t.py
done

# Le pipeline de bout en bout, sans clé ni réseau
cd intel-factory && PYTHONPATH=src python3 -m puakiller_intel run --family OneStart --seed onestart
```

```powershell
# Suites PowerShell, sur les deux moteurs
foreach ($t in 'Test-PuaRules','Test-RuleCatalog','Test-StatsUpdater','Test-OneBrowserGuard',
               'Test-ShiftBrowserGuard','Test-Logging','Test-ExecutionContext') {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tests\$t.ps1"
    pwsh -NoProfile -File "./tests/$t.ps1"
}
```

**Aucune règle de détection ni logique de suppression n'a été modifiée depuis `ff43b48`.**

Les sept phases sont terminées. Ce qui reste est hors du code : l'approbation CI par
`@ZER0Nep` sur les PR issues du fork, la réponse au vetting Hybrid Analysis, et — si Triage est
un jour activé — un premier `collect --dry-run` réel pour revérifier l'allowlist de champs
contre une réponse authentique, les cassettes étant écrites à la main faute d'accès.
