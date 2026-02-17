"""
sc4n3r — Markdown Report Generator
Produces professional-grade audit reports with executive summary,
OWASP coverage, priority matrix, attack chains, and PoCs.
"""

from datetime import datetime
from pathlib import Path

from .models import AuditReport, Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _code_snippet(file_path: str, start: int, end: int, context: int = 3) -> str:
    """Extract a code snippet with line numbers."""
    try:
        lines = Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
        s = max(0, start - context - 1)
        e = min(len(lines), (end or start) + context)
        return "\n".join(f"{i + 1:4d} | {lines[i]}" for i in range(s, e))
    except (IOError, OSError):
        return ""


def _severity_emoji(severity: str) -> str:
    return {
        "critical": "🔴", "high": "🟠", "medium": "🟡",
        "low": "⚪", "informational": "ℹ️",
    }.get(severity.lower(), "ℹ️")


def _risk_grade(report: AuditReport) -> tuple[str, str]:
    """Calculate overall risk grade (A-F) and description."""
    c = len(report.critical)
    h = len(report.high)
    m = len(report.medium)

    score = c * 25 + h * 10 + m * 3
    if score == 0:
        return "A", "Excellent — no significant security issues detected"
    if score <= 5:
        return "B", "Good — minor issues only, low risk"
    if score <= 15:
        return "C", "Moderate — some issues require attention before deployment"
    if score <= 30:
        return "D", "Concerning — significant issues found, remediation required"
    return "F", "Critical — severe vulnerabilities detected, do not deploy"


def _priority_bucket(finding: Finding) -> str:
    """Determine remediation priority bucket."""
    sev = finding.severity.lower()
    expl = finding.exploitability.lower() if finding.exploitability else ""

    if sev == "critical":
        return "Fix Now"
    if sev == "high":
        if expl == "high":
            return "Fix Now"
        return "Fix Before Deploy"
    if sev == "medium":
        if expl == "high":
            return "Fix Before Deploy"
        return "Consider Fixing"
    return "Accepted Risk"


# ---------------------------------------------------------------------------
# Finding formatters
# ---------------------------------------------------------------------------


def _format_finding_detail(finding: Finding, label: str) -> str:
    """Format a single finding with full details for the report."""
    parts: list[str] = []

    parts.append(f"### [{label}] {finding.title}\n")
    parts.append(f"**Location:** `{finding.location}`  ")
    if finding.swc_id or finding.swc:
        swc = finding.swc_id or finding.swc
        parts.append(f"**SWC:** [{swc}](https://swcregistry.io/docs/{swc})")
    if finding.owasp_category:
        parts.append(f"**OWASP:** {finding.owasp_category} — {finding.owasp_title}")
    parts.append("")

    # Priority bucket
    bucket = _priority_bucket(finding)
    if bucket:
        parts.append(f"**Priority:** {bucket}  ")
        if finding.exploitability:
            parts.append(f"**Exploitability:** {finding.exploitability}")
        parts.append("")

    # Description — prefer AI impact over raw tool description
    if finding.ai_analyzed and finding.impact and finding.impact != "N/A":
        parts.append(f"**Description:** {finding.impact}\n")
    elif finding.description:
        parts.append(f"**Description:** {finding.description}\n")

    # Proof of code
    if finding.line > 0:
        snippet = _code_snippet(finding.file, finding.line, finding.end_line or finding.line)
        if snippet:
            parts.append("**Proof of Code:**\n")
            parts.append(f"```solidity\n{snippet}\n```\n")

    # Attack scenario (from AI)
    if finding.ai_analyzed and finding.attack_scenario and finding.attack_scenario != "N/A":
        parts.append(f"**Attack Scenario:**\n{finding.attack_scenario}\n")

    # Recommendation / mitigation
    if finding.ai_analyzed and finding.suggested_fix:
        parts.append("**Recommendation:**\n")
        fix = finding.suggested_fix
        if "```" in fix:
            parts.append(f"{fix}\n")
        else:
            parts.append(f"```diff\n{fix}\n```\n")

    # Confidence score
    if finding.confidence > 0:
        conf_pct = int(finding.confidence * 100)
        conf_label = "Verified" if finding.poc_validated else ("High" if conf_pct >= 90 else "Medium" if conf_pct >= 70 else "Low")
        parts.append(f"**Confidence:** {conf_pct}% ({conf_label})\n")

    # PoC
    if finding.poc_code:
        if finding.poc_validated:
            parts.append("**Proof of Concept:** Verified — exploit confirmed executable\n")
        elif finding.poc_compiles:
            parts.append("**Proof of Concept:** Compiles — test execution pending\n")
        else:
            parts.append("**Proof of Concept:** Generated — not yet validated\n")
        parts.append("<details>\n<summary>PoC Code (Foundry Test)</summary>\n")
        parts.append(f"```solidity\n{finding.poc_code}\n```\n")
        parts.append("</details>\n")

    parts.append("---\n")
    return "\n".join(parts)


def _format_finding_line(finding: Finding) -> str:
    """One-line summary for low / informational findings."""
    return f"- **{finding.title}** — `{finding.location}`"


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------


def _generate_executive_summary(report: AuditReport, config: dict) -> str:
    """Generate professional executive summary section."""
    s: list[str] = []
    grade, grade_desc = _risk_grade(report)

    s.append("## Executive Summary\n")

    # Risk grade
    grade_colors = {"A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "F": "🔴"}
    s.append(f"**Overall Risk Grade: {grade_colors.get(grade, '')} {grade}** — {grade_desc}\n")

    # Key metrics
    s.append("| Metric | Value |")
    s.append("|--------|-------|")
    s.append(f"| Tools Run | {', '.join(report.tools_run) if report.tools_run else 'N/A'} |")
    s.append(f"| Raw Findings | {report.raw_count} |")
    s.append(f"| After Deduplication | {report.total + report.false_positive_count} |")
    if report.false_positive_count:
        s.append(f"| AI False Positives | {report.false_positive_count} |")
    s.append(f"| Confirmed Findings | {report.total} |")
    s.append("")

    # One-paragraph summary
    c, h, m = len(report.critical), len(report.high), len(report.medium)
    if c > 0:
        s.append(
            f"This scan identified **{c} critical** and **{h} high** severity "
            f"issue(s) that require immediate remediation before deployment. "
            f"Critical findings represent direct exploitation vectors that could "
            f"lead to loss of funds or protocol takeover.\n"
        )
    elif h > 0:
        s.append(
            f"This scan identified **{h} high** severity issue(s) that should be "
            f"addressed before deployment. While no critical exploits were found, "
            f"the high-severity findings represent significant security risks.\n"
        )
    elif m > 0:
        s.append(
            f"No critical or high severity issues were found. **{m} medium** "
            f"severity issue(s) were identified that should be reviewed and "
            f"addressed as part of standard security hardening.\n"
        )
    else:
        s.append(
            "No significant security issues were detected. The codebase follows "
            "security best practices for the patterns analyzed.\n"
        )

    return "\n".join(s)


# ---------------------------------------------------------------------------
# OWASP coverage matrix
# ---------------------------------------------------------------------------


def _generate_owasp_coverage(findings: list[Finding]) -> str:
    """Generate OWASP SC Top 10 coverage matrix."""
    from .owasp_mapping import OWASP_SC_TOP_10, get_owasp_coverage

    coverage = get_owasp_coverage(findings)
    s: list[str] = []
    s.append("## OWASP Smart Contract Top 10 Coverage\n")
    s.append("| # | Category | Checked | Findings |")
    s.append("|---|----------|---------|----------|")

    for code in sorted(coverage.keys()):
        info = coverage[code]
        checked = "✅" if info["checked"] else "—"
        count = info["finding_count"]
        count_str = f"**{count}**" if count > 0 else "0"
        s.append(f"| {code} | {info['title']} | {checked} | {count_str} |")

    s.append("")
    return "\n".join(s)


# ---------------------------------------------------------------------------
# Priority matrix
# ---------------------------------------------------------------------------


def _generate_priority_matrix(report: AuditReport) -> str:
    """Generate remediation priority matrix."""
    all_findings = report.critical + report.high + report.medium + report.low
    if not all_findings:
        return ""

    buckets: dict[str, list[Finding]] = {
        "Fix Now": [],
        "Fix Before Deploy": [],
        "Consider Fixing": [],
        "Accepted Risk": [],
    }
    for f in all_findings:
        bucket = _priority_bucket(f)
        buckets[bucket].append(f)

    s: list[str] = []
    s.append("## Remediation Priority\n")

    for bucket_name, bucket_findings in buckets.items():
        if not bucket_findings:
            continue
        emoji = {"Fix Now": "🚨", "Fix Before Deploy": "⚠️", "Consider Fixing": "📋", "Accepted Risk": "📝"}
        s.append(f"### {emoji.get(bucket_name, '')} {bucket_name} ({len(bucket_findings)})\n")
        for f in bucket_findings:
            sev_emoji = _severity_emoji(f.severity)
            s.append(f"- {sev_emoji} **{f.title}** — `{f.location}`")
        s.append("")

    return "\n".join(s)


# ---------------------------------------------------------------------------
# Attack chains section
# ---------------------------------------------------------------------------


def _generate_attack_chains(chains: list[dict]) -> str:
    """Generate attack chain section for the report."""
    if not chains:
        return ""

    s: list[str] = []
    s.append("## Attack Chains\n")
    s.append("*Multiple findings that combine into higher-severity attack paths:*\n")

    for chain in chains:
        sev = chain.get("severity", "high")
        emoji = _severity_emoji(sev)
        s.append(f"### {emoji} {chain.get('title', 'Attack Chain')}\n")
        s.append(f"**Combined Severity:** {sev.upper()}  ")
        s.append(f"**Findings Involved:** {', '.join(chain.get('findings', []))}\n")
        if chain.get("attack_path"):
            s.append(f"**Attack Path:**\n{chain['attack_path']}\n")
        if chain.get("combined_impact"):
            s.append(f"**Combined Impact:** {chain['combined_impact']}\n")
        s.append("---\n")

    return "\n".join(s)


# ---------------------------------------------------------------------------
# Full report (saved to file + artifact)
# ---------------------------------------------------------------------------


def generate_report(
    report: AuditReport, config: dict,
    attack_chains: list[dict] | None = None,
    checklist_section: str = "",
) -> str:
    """Generate the full markdown audit report."""
    today = datetime.now().strftime("%B %d, %Y")
    s: list[str] = []

    # Header
    s.append("# Smart Contract Security Audit Report\n")
    s.append(f"**Generated:** {today}  ")
    s.append(f"**Scanner:** sc4n3r v3.0.0  ")
    s.append(f"**Tools:** {', '.join(report.tools_run) if report.tools_run else 'N/A'}\n")

    # Executive summary
    s.append(_generate_executive_summary(report, config))

    # Summary table
    s.append("## Findings Summary\n")
    s.append("| Severity | Count |")
    s.append("|----------|-------|")
    s.append(f"| 🔴 Critical | {len(report.critical)} |")
    s.append(f"| 🟠 High | {len(report.high)} |")
    s.append(f"| 🟡 Medium | {len(report.medium)} |")
    s.append(f"| ⚪ Low | {len(report.low)} |")
    s.append(f"| ℹ️ Informational | {len(report.informational)} |")
    if report.false_positive_count:
        s.append(f"\n*AI filtered {report.false_positive_count} false positive(s).*")
    s.append("")

    # Priority matrix
    priority = _generate_priority_matrix(report)
    if priority:
        s.append(priority)

    # Attack chains
    if attack_chains:
        s.append(_generate_attack_chains(attack_chains))

    # OWASP coverage
    s.append(_generate_owasp_coverage(report.findings))

    # Checklist coverage
    if checklist_section:
        s.append(checklist_section)

    # Detailed sections: critical / high / medium
    for sev_name, prefix, findings in [
        ("Critical", "C", report.critical),
        ("High", "H", report.high),
        ("Medium", "M", report.medium),
    ]:
        if not findings:
            continue
        emoji = _severity_emoji(sev_name)
        s.append(f"## {emoji} {sev_name} Issues\n")
        for i, f in enumerate(findings, 1):
            s.append(_format_finding_detail(f, f"{prefix}-{i}"))

    # Low & informational — collapsed
    low_info = report.low + report.informational
    if low_info:
        s.append(f"<details>\n<summary>⚪ Low & Informational ({len(low_info)})</summary>\n")
        if report.low:
            s.append("### Low\n")
            for f in report.low:
                s.append(_format_finding_line(f))
            s.append("")
        if report.informational:
            s.append("### Informational\n")
            for f in report.informational:
                s.append(_format_finding_line(f))
            s.append("")
        s.append("</details>\n")

    if report.total == 0:
        s.append("**No security issues found.**\n")

    s.append("---")
    s.append("*Generated by [sc4n3r](https://sc4n3r.app) — Smart Contract Security Scanner*")
    return "\n".join(s)


# ---------------------------------------------------------------------------
# PR comment (posted to GitHub)
# ---------------------------------------------------------------------------


def generate_pr_comment(
    report: AuditReport, config: dict,
    attack_chains: list[dict] | None = None,
) -> str:
    """Generate a detailed PR comment with findings."""
    s: list[str] = []
    grade, grade_desc = _risk_grade(report)

    s.append("## 🔒 Security Audit Report\n")

    # Risk grade
    grade_colors = {"A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "F": "🔴"}
    s.append(f"**Risk Grade: {grade_colors.get(grade, '')} {grade}** — {grade_desc}\n")

    if report.has_critical or report.has_high:
        s.append("⚠️ **Action Required:** Critical / High severity issues found.\n")

    # Summary table
    s.append("| Severity | Count |")
    s.append("|----------|-------|")
    s.append(f"| 🔴 Critical | {len(report.critical)} |")
    s.append(f"| 🟠 High | {len(report.high)} |")
    s.append(f"| 🟡 Medium | {len(report.medium)} |")
    s.append(f"| ⚪ Low / Info | {len(report.low) + len(report.informational)} |")
    s.append("")

    # Attack chains (compact)
    if attack_chains:
        s.append("### ⛓️ Attack Chains Detected\n")
        for chain in attack_chains[:3]:
            sev = chain.get("severity", "high")
            emoji = _severity_emoji(sev)
            s.append(f"- {emoji} **{chain.get('title', 'Attack Chain')}** — {chain.get('combined_impact', '')}")
        s.append("")

    # Full detail for critical & high
    for sev_name, prefix, findings in [
        ("Critical", "C", report.critical),
        ("High", "H", report.high),
    ]:
        if not findings:
            continue
        emoji = _severity_emoji(sev_name)
        s.append(f"### {emoji} {sev_name}\n")
        for i, f in enumerate(findings, 1):
            s.append(_format_finding_detail(f, f"{prefix}-{i}"))

    # Medium — condensed
    if report.medium:
        s.append("### 🟡 Medium\n")
        for i, f in enumerate(report.medium, 1):
            s.append(f"**[M-{i}] {f.title}**")
            s.append(f"- Location: `{f.location}`")
            desc = f.description
            if f.ai_analyzed and f.impact and f.impact != "N/A":
                desc = f.impact
            if desc:
                short = desc[:250] + ("..." if len(desc) > 250 else "")
                s.append(f"- {short}")
            if f.ai_analyzed and f.suggested_fix:
                fix = f.suggested_fix[:200] + ("..." if len(f.suggested_fix) > 200 else "")
                s.append(f"- **Fix:** `{fix}`")
            s.append("")

    # Low / info — just a count
    low_info_count = len(report.low) + len(report.informational)
    if low_info_count:
        s.append(
            f"*Plus {low_info_count} low / informational finding(s) — see full report.*\n"
        )

    if report.total == 0:
        s.append("**No security issues found.**\n")

    s.append("---")
    s.append("*Powered by [sc4n3r](https://sc4n3r.app) — Smart Contract Security Scanner*")
    return "\n".join(s)


# ---------------------------------------------------------------------------
# Terminal report (printed to stdout)
# ---------------------------------------------------------------------------


def generate_terminal_report(report: AuditReport, config: dict) -> str:
    """Generate a clean, terminal-friendly audit report."""
    s: list[str] = []

    # Risk grade
    grade, grade_desc = _risk_grade(report)
    s.append(f"  Risk Grade: {grade} — {grade_desc}")
    s.append("")

    # Detailed sections: critical / high / medium
    for sev_name, prefix, findings in [
        ("Critical", "C", report.critical),
        ("High", "H", report.high),
        ("Medium", "M", report.medium),
    ]:
        if not findings:
            continue
        emoji = _severity_emoji(sev_name)
        s.append(f"  {emoji} {sev_name} Issues")
        s.append("  " + "─" * 45)
        for i, f in enumerate(findings, 1):
            s.append(f"  [{prefix}-{i}] {f.title}")
            s.append(f"  Location: {f.location}")
            if f.owasp_category:
                s.append(f"  OWASP: {f.owasp_category} — {f.owasp_title}")
            s.append("")

            if f.ai_analyzed and f.impact and f.impact != "N/A":
                s.append(f"  Description:")
                for line in f.impact.split("\n"):
                    s.append(f"    {line}")
                s.append("")
            elif f.description:
                s.append(f"  Description:")
                for line in f.description.split("\n"):
                    s.append(f"    {line}")
                s.append("")

            if f.line > 0:
                snippet = _code_snippet(f.file, f.line, f.end_line or f.line)
                if snippet:
                    s.append("  Code:")
                    for line in snippet.split("\n"):
                        s.append(f"    {line}")
                    s.append("")

            if f.ai_analyzed and f.attack_scenario and f.attack_scenario != "N/A":
                s.append("  Attack Scenario:")
                for line in f.attack_scenario.split("\n"):
                    s.append(f"    {line}")
                s.append("")

            if f.ai_analyzed and f.suggested_fix:
                s.append("  Recommendation:")
                for line in f.suggested_fix.split("\n"):
                    s.append(f"    {line}")
                s.append("")

            s.append("  " + "· " * 23)
            s.append("")

    # Low & informational — list format
    if report.low:
        s.append("  ⚪ Low Issues")
        s.append("  " + "─" * 45)
        for f in report.low:
            s.append(f"    • {f.title}")
            s.append(f"      {f.location}")
        s.append("")

    if report.informational:
        s.append("  ℹ️  Informational")
        s.append("  " + "─" * 45)
        for f in report.informational:
            s.append(f"    • {f.title}")
            s.append(f"      {f.location}")
        s.append("")

    if report.total == 0:
        s.append("  ✅ No security issues found.")
        s.append("")

    if report.false_positive_count:
        s.append(f"  AI filtered {report.false_positive_count} false positive(s).")
        s.append("")

    return "\n".join(s)
