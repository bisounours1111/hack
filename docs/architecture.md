# Rapport d'architecture — Équipe 5

Hackathon Lille Ynov Campus × OVHcloud — 6 & 7 juillet 2026
**Sujet : chaîne d'audit et de remédiation GitOps sécurisée sur Kubernetes.**

## 1. La boucle cible

```
Détection d'une faille (Trivy) → analyse & correctif proposé par l'IA (AI Endpoints OVHcloud)
→ Pull Request automatique sur GitHub → revue humaine → merge
→ resynchronisation Argo CD → cluster corrigé
```

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│              Cluster Managed Kubernetes OVHcloud             │
│                                                              │
│  ┌──────────┐  ┌────────────────┐  ┌─────────┐  ┌────────┐  │
│  │ Argo CD  │  │ Trivy-operator │  │ Kyverno │  │ Falco  │  │
│  │ (GitOps) │  │ (CVE + config) │  │(policies)│ │(runtime)│ │
│  └────┬─────┘  └───────┬────────┘  └─────────┘  └────────┘  │
│       │                │              ┌────────────┐         │
│       │                ▼              │ Prometheus │         │
│       │        ┌───────────────┐      │ + Grafana  │         │
│       │        │  Remediator   │      └────────────┘         │
│       │        │ (CronJob 15m) │──────► AI Endpoints OVH     │
│       │        └───────┬───────┘        (IA générative)      │
└───────┼────────────────┼─────────────────────────────────────┘
        │                │ ouvre une Pull Request
        │                ▼
        │        ┌───────────────┐
        └────────│  Dépôt GitHub │ ◄── revue humaine + merge
   synchronise   │ bisounours1111/hack │
                 └───────────────┘
```

## 3. Rôle de chaque brique et circulation de l'information

- **Argo CD (GitOps)** — pattern *app-of-apps* : `root-app.yaml` pointe sur `infra/argocd-apps/`, qui déclare toutes les Applications (outils Helm + workloads du repo). `prune` + `selfHeal` activés : le cluster est toujours identique à Git. Seul Argo CD lui-même est installé à la main (amorçage).
- **Trivy-operator (détection)** — scanne en continu images et configurations, publie des `VulnerabilityReports` (CVE, avec `fixedVersion`) et des `ConfigAuditReports` (privileged, root, limits absentes). Ce sont les CRD que consomme le remediator. `serviceMonitor.enabled: true` expose les métriques à Prometheus.
- **Kyverno (policy-as-code)** — 3 ClusterPolicies en mode **Audit** (`policies/`) : conteneurs privilégiés interdits, limits CPU/mémoire obligatoires, tag `:latest` interdit. Le mode Audit est un choix assumé : en Enforce, notre propre app vulnérable serait bloquée et il n'y aurait rien à démontrer. Les `PolicyReports` sont une 2e source de détection.
- **Falco (runtime)** — driver `modern_ebpf` (adapté au cluster managé OVH, aucun module noyau à compiler) + Falcosidekick UI. Complète le statique par du comportemental : shell dans un conteneur, lecture de `/etc/shadow`...
- **Prometheus + Grafana (observabilité)** — kube-prometheus-stack ; collecte `trivy_image_vulnerabilities` pour tracer la courbe de CVE critiques qui chute au merge de la PR.
- **Remediator (notre code, `apps/remediator/`)** — CronJob Python : lit les rapports Trivy, lit le manifest dans **Git** (source de vérité), demande le correctif à **AI Endpoints OVHcloud**, valide le YAML retourné, ouvre une PR. Détail dans `apps/remediator/README.md`.
- **Cible (`apps/vulnerable-app/`)** — Deployment volontairement vulnérable : `nginx:1.14` (CVE 2018), `privileged: true`, `runAsUser: 0`, aucune limit. Rejouable à volonté par `git revert` du correctif.

## 4. Choix d'architecture

| Choix | Justification |
| --- | --- |
| Trivy plutôt que Kubescape | Rapports en CRD (`VulnerabilityReports`) simples à consommer par un script ; `fixedVersion` donne directement la cible de mise à jour. |
| Kyverno en mode Audit | Garder l'app vulnérable déployable pour la démo ; les violations restent visibles dans les PolicyReports. |
| CronJob in-cluster plutôt que script local | Déclenchement automatisé, déployé par Argo CD ; `load_incluster_config()` + ServiceAccount RBAC lecture seule sur les CRD Trivy (pas de kubeconfig dans le cluster). |
| Secrets hors Git | Token GitHub et clé IA injectés via un Secret Kubernetes créé à la main (`.env` gitignoré). Piste d'amélioration : External Secrets Operator (CNCF Incubating). |
| Revue humaine obligatoire | Le garde-fou de la chaîne : l'IA propose, l'humain valide. Une PR anti-doublon évite le spam. |

## 5. Limites et améliorations possibles

- Le remediator cible un seul manifest (`MANIFEST_PATH`) ; généralisable en mappant chaque rapport Trivy vers son fichier Git.
- Pas encore de `kubectl apply --dry-run=server` sur le YAML de l'IA avant PR (boucle de retry avec le message d'erreur).
- Alertes Falco non encore reliées à l'IA (piste : issue GitHub générée sur alerte critique).
- Gestion des secrets à migrer vers ESO.

## 6. Tableau récapitulatif du statut CNCF

| Composant | Rôle dans la chaîne | Statut CNCF |
| --- | --- | --- |
| Argo CD | GitOps — synchronisation Git → cluster | Graduated |
| Trivy-operator | Audit de sécurité (CVE + config) | Projet Aqua Security, scanner validé CNCF |
| Kyverno | Policy-as-code | Graduated |
| Falco | Détection de menaces runtime | Graduated |
| Prometheus | Observabilité & métriques | Graduated |
| Kubernetes (MKS OVHcloud) | Orchestration | Graduated |
| Helm (via Argo CD) | Packaging des composants | Graduated |
| Kustomize (remediator) | Composition des manifests | Sous-projet Kubernetes |
| AI Endpoints | Couche d'IA générative | OVHcloud (hors CNCF — assumé dans le brief) |
| (option) External Secrets Operator | Gestion des secrets | Incubating |
