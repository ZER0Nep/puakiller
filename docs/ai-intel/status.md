# État du chantier IA — phases 0 à 4

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
| 5 | Publication Issue / Draft PR | non commencée | — |
| 6 | Serveur distant (Linux) | non commencée | — |
| 7 | Triage optionnel | non commencée | — |

Les quatre branches sont **empilées** et doivent être relues dans l'ordre :

```
feat/rule-catalog-compiler          -> #1
  feat/intel-factory-offline        -> #2
    feat/hybrid-analysis-readonly   -> #3
      feat/llm-scout-critic         -> #4
```

## Ce qui bloque

**La CI n'a jamais tourné sur ces PR.** Elles viennent d'un fork (`iPresing/puakiller`), et
GitHub exige qu'un mainteneur autorise l'exécution des workflows pour la première contribution
d'un compte depuis un fork. Un clic de `@ZER0Nep` sur « Approve and run workflows » suffit.

Tout a donc été vérifié **localement**, y compris depuis un clone neuf de la branche :

- 7 suites PowerShell × 2 moteurs (Windows PowerShell 5.1 et PowerShell 7.6.5)
- `scripts/verify-generated.py` — 5 contrôles
- 127 tests Python, tous hors ligne

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

---

## Invariants qu'aucune phase suivante ne doit défaire

1. Aucune règle de suppression n'est auto-fusionnée. Les PR restent en **draft**.
2. Aucun échantillon ne peut être soumis. `transport.py` reste sans corps de requête.
3. Aucune donnée SOC n'entre. Le filtre échoue fermé et nomme la classe, jamais la valeur.
4. Aucun modèle ne peut bloquer ni approuver.
5. `.reveal()` n'existe qu'à deux endroits — clé bac à sable, clé modèle. Un test échoue au
   troisième.
6. Le mode par défaut (`fixture`) ne joint aucun hôte, et la CI ne peut faire aucun appel payant.
7. La sémantique de détection est figée par le golden
   `docs/ai-intel/baseline-results/rules-golden.txt` (`sha256 dfe4f76c…`).

---

## Pour reprendre

```bash
# Tout est-il encore vert ?
python3 scripts/verify-generated.py
python3 tests/compiler/test_escape.py
for t in test_intel_factory test_hybrid_analysis test_llm_roles; do
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
