# Remediator — couche d'enrichissement IA

Le remediator est la brique développée par l'équipe : il ferme la boucle
**détection → analyse IA → Pull Request → revue humaine → merge → resync Argo CD**.

## Ce qu'il fait, en 5 temps

1. Lit les `VulnerabilityReports` **et** les `ConfigAuditReports` (CRD de trivy-operator) dans le namespace `demo`.
2. Récupère le manifest concerné (`apps/vulnerable-app/deployment.yaml`) depuis **GitHub** — Git est la source de vérité, pas le cluster.
3. Envoie le résumé des failles + le manifest actuel à **AI Endpoints OVHcloud** (API compatible OpenAI) qui renvoie une explication et le YAML corrigé.
4. Valide le YAML (parsable, `kind: Deployment`), crée une branche `fix/auto-remediation-<timestamp>` et committe le correctif.
5. Ouvre une **Pull Request** avec l'explication de l'IA et la liste des CVE en description. La revue humaine avant merge est le garde-fou de la chaîne.

Anti-doublon : si une PR de remédiation est déjà ouverte, le script ne fait rien.

## Variables d'environnement

| Variable | Description |
| --- | --- |
| `OVH_AI_BASE_URL` | URL de base du modèle AI Endpoints (ex. `https://oai.endpoints.kepler.ai.cloud.ovh.net/v1`) |
| `OVH_AI_TOKEN` | Token AI Endpoints OVHcloud |
| `OVH_AI_MODEL` | Nom exact du modèle (ex. `Meta-Llama-3_3-70B-Instruct`) |
| `GITHUB_TOKEN` | Fine-grained PAT avec `Contents: RW` + `Pull requests: RW` |
| `GITHUB_REPO` | Repo cible (défaut : `bisounours1111/hack`) |
| `GITHUB_BRANCH` | Branche de base (défaut : `main`) |
| `TARGET_NAMESPACE` | Namespace scanné (défaut : `demo`) |
| `MANIFEST_PATH` | Manifest à corriger (défaut : `apps/vulnerable-app/deployment.yaml`) |

## Lancer en local

```bash
pip install -r requirements.txt
export $(grep -v '^#' ../../.env | xargs)
export KUBECONFIG=../../equipe-5.yaml

# Sans créer de PR (détection + appel IA seulement) :
python remediator.py --dry-run

# Boucle complète (ouvre la PR) :
python remediator.py
```

## Exécution dans le cluster (mode GitOps)

Le dossier est déployé par Argo CD (`infra/argocd-apps/remediator.yaml`) via Kustomize :

- `cronjob.yaml` — exécution toutes les 15 min, le code est monté depuis un ConfigMap ;
- `rbac.yaml` — ServiceAccount + Role **lecture seule** sur les CRD Trivy (le script utilise `load_incluster_config()`) ;
- `secret.yaml` — template du Secret ; les vraies valeurs sont créées à la main (jamais commitées) :

```bash
kubectl create secret generic remediator-secrets -n demo \
  --from-env-file=../../.env \
  --dry-run=client -o yaml | kubectl apply -f -
```

Déclenchement manuel pour la démo :

```bash
kubectl create job --from=cronjob/remediator remediator-demo -n demo
kubectl logs -n demo -l app=remediator -f
```
