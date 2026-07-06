# Hackathon GitOps — Audit & Remédiation OVHcloud (Équipe 5)

Chaîne d'audit et de remédiation GitOps sur Managed Kubernetes OVHcloud :

> Détection d'une faille (Trivy) → analyse & correctif par l'IA (AI Endpoints OVHcloud) → Pull Request automatique → revue humaine → merge → resynchronisation Argo CD → cluster corrigé

Rapport d'architecture + tableau CNCF : [`docs/architecture.md`](docs/architecture.md) · Scénario de démo : [`docs/demo.md`](docs/demo.md) · Couche IA : [`apps/remediator/README.md`](apps/remediator/README.md)

## Prérequis

- `kubectl` configuré avec le kubeconfig du cluster (`equipe-5.yaml`)
- Repo GitHub : https://github.com/bisounours1111/hack
- Token OVH AI Endpoints + PAT GitHub (scope `repo`)

## Bootstrap Argo CD

```bash
export KUBECONFIG=./equipe-5.yaml

kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl wait --for=condition=available deployment/argocd-server -n argocd --timeout=300s

# Mot de passe admin
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d && echo
```

## Déploiement GitOps

1. Pousser le dépôt sur GitHub (`main`) : https://github.com/bisounours1111/hack
2. Enregistrer le repo dans Argo CD (UI ou CLI).
3. Appliquer l'App of Apps :

```bash
kubectl apply -f root-app.yaml
```

Ou appliquer les Applications Helm directement (sans root-app) :

```bash
kubectl apply -f infra/argocd-apps/trivy-operator.yaml
kubectl apply -f infra/argocd-apps/kyverno.yaml
kubectl apply -f infra/argocd-apps/prometheus.yaml
kubectl apply -f infra/argocd-apps/falco.yaml
kubectl apply -f infra/argocd-apps/kyverno-policies.yaml
kubectl apply -f infra/argocd-apps/vulnerable-app.yaml
kubectl apply -f infra/argocd-apps/remediator.yaml
```

## Secret remediator

```bash
cp .env.example .env   # compléter les valeurs
kubectl create secret generic remediator-secrets -n demo \
  --from-env-file=.env \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Test local du remediator

```bash
pip install -r apps/remediator/requirements.txt
export $(grep -v '^#' .env | xargs)
python apps/remediator/remediator.py --dry-run
```

## Vérifications

```bash
kubectl get applications -n argocd
kubectl get vulnerabilityreports -n demo
kubectl get configauditreports -n demo
kubectl get policyreports -n demo
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep -i warning
kubectl create job --from=cronjob/remediator manual-run -n demo
```

## Interfaces (chacune dans son terminal)

```bash
kubectl port-forward svc/argocd-server -n argocd 8080:443
kubectl port-forward svc/prometheus-grafana -n monitoring 3000:80      # admin / hackathon2026
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802:2802     # admin / admin
```

## Structure

```
├── root-app.yaml          # App of Apps (seul kubectl apply manuel après Argo CD)
├── infra/argocd-apps/     # Applications Argo CD (Trivy, Kyverno, Prometheus, Falco, apps)
├── policies/              # ClusterPolicies Kyverno (mode Audit)
├── apps/vulnerable-app/   # Cible volontairement vulnérable (4 familles de failles)
├── apps/remediator/       # Couche IA : script + CronJob + RBAC (voir son README)
└── docs/                  # Rapport d'architecture, tableau CNCF, scénario de démo
```

Règle d'or : après le bootstrap d'Argo CD et de la root-app, plus rien ne s'installe à la main — tout passe par Git.
