# Hackathon GitOps — Audit & Remédiation OVHcloud

Chaîne GitOps sécurisée : détection (Trivy/Kyverno/Falco) → analyse IA (OVH AI Endpoints) → PR GitHub → merge → resync Argo CD.

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
kubectl get vulnerabilityreports -n demo
kubectl get policyreport -A
kubectl get applications -n argocd
kubectl create job --from=cronjob/remediator manual-run -n demo
```

## Structure

```
├── root-app.yaml
├── infra/argocd-apps/     # Applications Argo CD
├── policies/              # Kyverno (mode Audit)
├── apps/vulnerable-app/   # Cible volontairement vulnérable
└── apps/remediator/       # Script IA + CronJob
```
