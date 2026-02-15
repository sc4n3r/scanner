"""
sc4n3r — GitHub Inline Review Comments
Posts comments directly on the lines where issues are found in changed files.
"""

import logging
import os
from typing import Optional

import requests

from .models import AuditReport

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


def _get_pr_info() -> Optional[tuple[str, str, int]]:
    """Extract (owner, repo, pr_number) from GitHub environment."""
    repo = os.getenv("GITHUB_REPOSITORY")  # owner/repo
    ref = os.getenv("GITHUB_REF", "")  # refs/pull/123/merge

    if not repo or "/pull/" not in ref:
        return None
    try:
        owner, name = repo.split("/")
        pr_number = int(ref.split("/")[2])
        return owner, name, pr_number
    except (ValueError, IndexError):
        return None


def _get_changed_files(
    owner: str, repo: str, pr: int, token: str,
) -> set[str]:
    """Return the set of file paths changed in the PR."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr}/files"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return {f["filename"] for f in resp.json()}
    except requests.RequestException as e:
        log.warning(f"Failed to fetch PR files: {e}")
    return set()


def post_review_comments(report: AuditReport, token: str) -> bool:
    """Post inline comments on the PR for findings in changed files."""
    pr_info = _get_pr_info()
    if not pr_info:
        log.info("Inline: not a PR, skipping")
        return False

    owner, repo, pr_number = pr_info
    commit_sha = os.getenv("GITHUB_SHA", "")
    if not commit_sha:
        log.warning("Inline: no GITHUB_SHA")
        return False

    changed = _get_changed_files(owner, repo, pr_number, token)
    if not changed:
        return False

    severity_emoji = {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪",
    }

    comments = []
    for finding in report.critical + report.high + report.medium + report.low:
        path = finding.file.lstrip("./")
        if path not in changed or finding.line <= 0:
            continue

        emoji = severity_emoji.get(finding.severity.lower(), "ℹ️")
        body = f"{emoji} **{finding.severity.upper()}: {finding.title}**\n\n"

        if finding.description:
            body += f"{finding.description[:300]}\n\n"

        if finding.ai_analyzed and finding.attack_scenario and finding.attack_scenario != "N/A":
            body += f"**Attack Scenario:** {finding.attack_scenario[:200]}\n\n"

        if finding.ai_analyzed and finding.suggested_fix:
            fix = finding.suggested_fix[:300]
            if "```" not in fix:
                body += f"**Fix:**\n```solidity\n{fix}\n```\n"
            else:
                body += f"**Fix:**\n{fix}\n"

        comments.append({"path": path, "line": finding.line, "body": body})

    if not comments:
        return True

    # GitHub limits inline comments per review
    comments = comments[:20]

    url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    payload = {
        "commit_id": commit_sha,
        "body": f"🔒 **sc4n3r** found {len(comments)} issue(s) in changed files.",
        "event": "COMMENT",
        "comments": comments,
    }

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        if resp.status_code == 200:
            log.info(f"Posted {len(comments)} inline comment(s)")
            return True
        log.warning(f"Inline comments failed ({resp.status_code}): {resp.text[:200]}")
    except requests.RequestException as e:
        log.error(f"Inline comments error: {e}")
    return False
