"""
sc4n3r — SARIF Output Generator
Converts audit findings to SARIF v2.1.0 for GitHub Security Tab integration.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import AuditReport, Finding


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}

SEVERITY_TO_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "informational": "1.0",
}


def _build_rule(finding: Finding) -> dict:
    """Build a SARIF reporting descriptor (rule) from a finding."""
    rule: dict = {
        "id": finding.id,
        "name": finding.title.replace(" ", ""),
        "shortDescription": {"text": finding.title},
        "properties": {
            "tags": ["security", "smart-contract"],
            "security-severity": SEVERITY_TO_SECURITY_SEVERITY.get(
                finding.severity.lower(), "3.0"
            ),
        },
    }

    desc_parts = []
    if finding.description:
        desc_parts.append(finding.description)
    if finding.owasp_category:
        desc_parts.append(f"OWASP: {finding.owasp_category} — {finding.owasp_title}")
    if finding.swc_id:
        desc_parts.append(f"SWC: {finding.swc_id}")
    if desc_parts:
        rule["fullDescription"] = {"text": " | ".join(desc_parts)}

    help_parts = []
    if finding.ai_analyzed and finding.impact and finding.impact != "N/A":
        help_parts.append(f"**Impact:** {finding.impact}")
    if finding.ai_analyzed and finding.attack_scenario and finding.attack_scenario != "N/A":
        help_parts.append(f"**Attack Scenario:** {finding.attack_scenario}")
    if finding.ai_analyzed and finding.suggested_fix:
        help_parts.append(f"**Fix:** {finding.suggested_fix}")
    if help_parts:
        rule["help"] = {
            "text": "\n\n".join(help_parts),
            "markdown": "\n\n".join(help_parts),
        }

    return rule


def _build_result(finding: Finding, rule_index: int) -> dict:
    """Build a SARIF result from a finding."""
    level = SEVERITY_TO_SARIF_LEVEL.get(finding.severity.lower(), "note")

    message_parts = [finding.title]
    if finding.ai_analyzed and finding.impact and finding.impact != "N/A":
        message_parts.append(finding.impact)
    elif finding.description:
        message_parts.append(finding.description)

    result: dict = {
        "ruleId": finding.id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": " — ".join(message_parts)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(finding.line, 1),
                    },
                }
            }
        ],
        "properties": {
            "severity": finding.severity,
            "tool": finding.tool,
        },
    }

    if finding.end_line and finding.end_line > finding.line:
        result["locations"][0]["physicalLocation"]["region"]["endLine"] = finding.end_line

    if finding.owasp_category:
        result["properties"]["owasp"] = f"{finding.owasp_category}: {finding.owasp_title}"
    if finding.swc_id:
        result["properties"]["swc"] = finding.swc_id
    if finding.ai_analyzed:
        result["properties"]["aiAnalyzed"] = True
        result["properties"]["falsePositive"] = finding.is_false_positive

    # Fingerprint for deduplication
    result["fingerprints"] = {
        "sc4n3r/v1": finding.dedup_key(),
    }

    return result


def generate_sarif(report: AuditReport, config: dict) -> str:
    """Generate SARIF v2.1.0 JSON string from an audit report."""

    # Collect confirmed findings (exclude false positives)
    confirmed = [
        f for f in report.findings if not f.is_false_positive
    ]

    # Build rules (deduplicated by rule ID)
    rule_map: dict[str, int] = {}
    rules: list[dict] = []
    for finding in confirmed:
        if finding.id not in rule_map:
            rule_map[finding.id] = len(rules)
            rules.append(_build_rule(finding))

    # Build results
    results = []
    for finding in confirmed:
        rule_index = rule_map.get(finding.id, 0)
        results.append(_build_result(finding, rule_index))

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sc4n3r",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://sc4n3r.app",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "properties": {
                    "toolsRun": report.tools_run,
                    "totalFindings": report.total,
                    "falsePositivesFiltered": report.false_positive_count,
                },
            }
        ],
    }

    return json.dumps(sarif, indent=2)


def save_sarif(report: AuditReport, config: dict, output_path: str = "results/sc4n3r.sarif") -> str:
    """Generate and save SARIF report to file. Returns the file path."""
    sarif_json = generate_sarif(report, config)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(sarif_json, encoding="utf-8")
    return str(path)
