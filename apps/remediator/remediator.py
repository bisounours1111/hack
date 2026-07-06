#!/usr/bin/env python3
"""GitOps security remediator: reads Trivy reports, calls OVH AI, opens a GitHub PR."""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

import yaml
from github import Github, GithubException
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from openai import OpenAI

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("remediator")

TRIVY_GROUP = "aquasecurity.github.io"
TRIVY_VERSION = "v1alpha1"
TRIVY_PLURAL = "vulnerabilityreports"
TARGET_NAMESPACE = os.environ.get("TARGET_NAMESPACE", "demo")
MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "apps/vulnerable-app/deployment.yaml")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "ORG/hackathon-gitops")
GITHUB_BRANCH = os.environ.get("GITHUB_BRANCH", "main")
ACTIONABLE_SEVERITIES = {"CRITICAL", "HIGH"}

SYSTEM_PROMPT = """Tu es un expert Kubernetes et DevSecOps.
Tu dois corriger un manifest Deployment vulnérable.

Réponds UNIQUEMENT avec ce format exact, sans texte avant ou après :

EXPLICATION:
<analyse concise en français des failles et des corrections appliquées>

YAML:
```yaml
<manifest Deployment complet et valide>
```

Corrections obligatoires :
- Mettre à jour l'image nginx vers une version sans CVE HIGH/CRITICAL connues
- Supprimer privileged: true (ou le mettre à false)
- Forcer runAsNonRoot: true et runAsUser non-root (ex: 101)
- Ajouter resources.limits pour cpu et memory
- Conserver namespace, labels et structure du manifest original
- Ne retourner qu'un seul manifest Deployment YAML valide
"""


def load_kube_config() -> None:
    try:
        config.load_incluster_config()
        logger.info("Using in-cluster Kubernetes configuration")
    except config.ConfigException:
        config.load_kube_config()
        logger.info("Using local kubeconfig")


def list_vulnerability_reports(namespace: str) -> list[dict[str, Any]]:
    load_kube_config()
    api = client.CustomObjectsApi()
    try:
        result = api.list_namespaced_custom_object(
            group=TRIVY_GROUP,
            version=TRIVY_VERSION,
            namespace=namespace,
            plural=TRIVY_PLURAL,
        )
    except ApiException as exc:
        logger.error("Failed to list VulnerabilityReports: %s", exc)
        raise
    return result.get("items", [])


def extract_actionable_findings(reports: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: set[str] = set()

    for report in reports:
        report_name = report.get("metadata", {}).get("name", "unknown")
        vulnerabilities = report.get("report", {}).get("vulnerabilities", []) or []
        for vuln in vulnerabilities:
            severity = (vuln.get("severity") or "").upper()
            if severity not in ACTIONABLE_SEVERITIES:
                continue
            vuln_id = vuln.get("vulnerabilityID", "unknown")
            key = f"{report_name}:{vuln_id}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "report": report_name,
                    "vulnerability_id": vuln_id,
                    "severity": severity,
                    "resource": vuln.get("resource", "n/a"),
                    "fixed_version": vuln.get("fixedVersion") or "unknown",
                    "title": vuln.get("title", ""),
                }
            )
    return findings


def fetch_manifest_from_github(token: str, repo_name: str, path: str, branch: str) -> tuple[str, str | None]:
    gh = Github(token)
    repo = gh.get_repo(repo_name)
    try:
        content_file = repo.get_contents(path, ref=branch)
        if isinstance(content_file, list):
            raise ValueError(f"Path {path} is a directory, expected a file")
        sha = content_file.sha
        content = content_file.decoded_content.decode("utf-8")
        return content, sha
    except GithubException as exc:
        logger.error("Failed to fetch manifest from GitHub: %s", exc)
        raise


def build_user_prompt(findings: list[dict[str, str]], manifest_yaml: str) -> str:
    findings_text = yaml.safe_dump(findings, allow_unicode=True, sort_keys=False)
    return (
        "Voici les failles détectées par Trivy (CRITICAL/HIGH) :\n"
        f"{findings_text}\n"
        "Voici le manifest Deployment actuel :\n"
        f"{manifest_yaml}\n"
        "Produis le manifest corrigé selon le format demandé."
    )


def call_ai(system_prompt: str, user_prompt: str) -> str:
    base_url = os.environ["OVH_AI_BASE_URL"]
    api_key = os.environ["OVH_AI_TOKEN"]
    model = os.environ["OVH_AI_MODEL"]

    client_ai = OpenAI(base_url=base_url, api_key=api_key)
    response = client_ai.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,
    )
    return response.choices[0].message.content or ""


def parse_ai_response(response_text: str) -> tuple[str, str]:
    explanation_match = re.search(
        r"EXPLICATION:\s*(.*?)\s*YAML:",
        response_text,
        re.DOTALL | re.IGNORECASE,
    )
    yaml_match = re.search(r"```(?:yaml)?\s*(.*?)```", response_text, re.DOTALL | re.IGNORECASE)

    if not yaml_match:
        raise ValueError("AI response does not contain a YAML code block")

    explanation = explanation_match.group(1).strip() if explanation_match else "Remédiation automatique générée par l'IA."
    yaml_content = yaml_match.group(1).strip()
    return explanation, yaml_content


def validate_manifest(yaml_content: str) -> str:
    parsed = yaml.safe_load(yaml_content)
    if not isinstance(parsed, dict):
        raise ValueError("Corrected manifest is not a valid YAML object")
    if parsed.get("kind") != "Deployment":
        raise ValueError("Corrected manifest must be a Deployment")
    return yaml.dump(parsed, sort_keys=False, allow_unicode=True)


def has_open_remediation_pr(token: str, repo_name: str) -> bool:
    gh = Github(token)
    repo = gh.get_repo(repo_name)
    pulls = repo.get_pulls(state="open", base=GITHUB_BRANCH)
    for pull in pulls:
        title = pull.title or ""
        if "Remédiation sécurité vulnerable-app" in title or "Auto] Remédiation" in title:
            logger.info("Open remediation PR already exists: #%s", pull.number)
            return True
    return False


def create_remediation_pr(
    token: str,
    repo_name: str,
    path: str,
    branch: str,
    new_content: str,
    old_sha: str | None,
    explanation: str,
    findings: list[dict[str, str]],
    dry_run: bool = False,
) -> None:
    if dry_run:
        logger.info("Dry-run mode: skipping PR creation")
        logger.info("Explanation:\n%s", explanation)
        logger.info("Corrected YAML:\n%s", new_content)
        return

    gh = Github(token)
    repo = gh.get_repo(repo_name)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    fix_branch = f"fix/auto-remediation-{timestamp}"

    base_ref = repo.get_git_ref(f"heads/{branch}")
    repo.create_git_ref(ref=f"refs/heads/{fix_branch}", sha=base_ref.object.sha)

    cve_list = "\n".join(
        f"- {item['vulnerability_id']} ({item['severity']}) — fix: {item['fixed_version']}"
        for item in findings
    )
    commit_message = f"fix(security): remediate vulnerable-app ({len(findings)} findings)"
    pr_body = (
        "## Remédiation automatique (OVH AI Endpoints)\n\n"
        f"{explanation}\n\n"
        "## CVE détectées\n\n"
        f"{cve_list}\n\n"
        "---\n"
        "*PR générée automatiquement par le remediator hackathon.*"
    )

    if old_sha:
        repo.update_file(
            path=path,
            message=commit_message,
            content=new_content,
            sha=old_sha,
            branch=fix_branch,
        )
    else:
        repo.create_file(
            path=path,
            message=commit_message,
            content=new_content,
            branch=fix_branch,
        )

    pr = repo.create_pull(
        title="[Auto] Remédiation sécurité vulnerable-app",
        body=pr_body,
        head=fix_branch,
        base=branch,
    )
    logger.info("Pull request created: #%s %s", pr.number, pr.html_url)


def run(dry_run: bool = False) -> int:
    required_env = ["OVH_AI_BASE_URL", "OVH_AI_TOKEN", "OVH_AI_MODEL", "GITHUB_TOKEN"]
    missing = [name for name in required_env if not os.environ.get(name)]
    if missing and not dry_run:
        logger.error("Missing required environment variables: %s", ", ".join(missing))
        return 1

    logger.info("Scanning VulnerabilityReports in namespace %s", TARGET_NAMESPACE)
    reports = list_vulnerability_reports(TARGET_NAMESPACE)
    findings = extract_actionable_findings(reports)

    if not findings:
        logger.info("No CRITICAL/HIGH vulnerabilities found. Nothing to remediate.")
        return 0

    logger.info("Found %d actionable vulnerabilities", len(findings))
    for item in findings:
        logger.info(
            "  %s [%s] %s (fix: %s)",
            item["vulnerability_id"],
            item["severity"],
            item["resource"],
            item["fixed_version"],
        )

    github_token = os.environ.get("GITHUB_TOKEN", "")
    if not dry_run and has_open_remediation_pr(github_token, GITHUB_REPO):
        logger.info("Skipping remediation: an open PR already exists.")
        return 0

    manifest_yaml, manifest_sha = fetch_manifest_from_github(
        github_token or "dry-run",
        GITHUB_REPO,
        MANIFEST_PATH,
        GITHUB_BRANCH,
    ) if not dry_run else ("", None)

    if dry_run:
        manifest_yaml = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: demo
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:1.14
          securityContext:
            privileged: true
"""

    user_prompt = build_user_prompt(findings, manifest_yaml)
    logger.info("Calling OVH AI Endpoints model %s", os.environ.get("OVH_AI_MODEL", "unknown"))
    ai_response = call_ai(SYSTEM_PROMPT, user_prompt)
    explanation, corrected_yaml = parse_ai_response(ai_response)
    validated_yaml = validate_manifest(corrected_yaml)

    create_remediation_pr(
        token=github_token,
        repo_name=GITHUB_REPO,
        path=MANIFEST_PATH,
        branch=GITHUB_BRANCH,
        new_content=validated_yaml,
        old_sha=manifest_sha,
        explanation=explanation,
        findings=findings,
        dry_run=dry_run,
    )
    logger.info("Remediation workflow completed successfully")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="GitOps security remediator")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run detection and AI analysis without creating a GitHub PR",
    )
    args = parser.parse_args()
    try:
        sys.exit(run(dry_run=args.dry_run))
    except Exception as exc:
        logger.exception("Remediation failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
