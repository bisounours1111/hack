# Scénario de démo — 10 minutes chrono

Avant de parler : lancer les port-forwards dans des terminaux séparés.

```bash
export KUBECONFIG=./equipe-5.yaml
kubectl port-forward svc/argocd-server -n argocd 8080:443
kubectl port-forward svc/prometheus-grafana -n monitoring 3000:80          # admin / hackathon2026
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802:2802         # admin / admin
```

## Déroulé

1. **(1 min) GitOps** — montrer le repo GitHub et l'UI Argo CD : root-app + toutes les Applications `Synced / Healthy`. "Tout ce qui tourne vient de Git."
2. **(1 min) Détection** — l'app vulnérable et ses rapports :

```bash
kubectl get vulnerabilityreports -n demo
kubectl get configauditreports -n demo
```

   Plus le dashboard Grafana avec `sum(trivy_image_vulnerabilities{severity="Critical"})`.
3. **(1 min) Policies + runtime** — violation Kyverno puis alerte Falco en live :

```bash
kubectl get policyreports -n demo
kubectl exec -it deploy/vulnerable-app -n demo -- sh -c "cat /etc/shadow"
```

4. **(2 min) Remédiation IA** — déclencher le remediator, la PR s'ouvre en direct :

```bash
kubectl create job --from=cronjob/remediator remediator-demo -n demo
kubectl logs -n demo -l app=remediator -f
```

5. **(2 min) Revue humaine** — lire la PR (explication de l'IA, liste des CVE), merger devant le jury.
6. **(2 min) Boucle fermée** — Argo CD resynchronise (≤3 min), nouveau pod sain, courbe Grafana qui chute.
7. **(1 min) Conclusion** — tableau CNCF (`docs/architecture.md`), limites et améliorations.

## Rejouer la boucle

```bash
git revert <commit-du-correctif> && git push
# Argo CD redéploie la version vulnérable → prêt pour refaire la démo
```

## Plan B

Captures d'écran / enregistrement de chaque étape à préparer mardi matin, au cas où le Wi-Fi ou le cluster flanche pendant la soutenance.
