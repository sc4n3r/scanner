"""
sc4n3r — Markdown Report Generator
Produces full audit reports and condensed PR comments.
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


# ---------------------------------------------------------------------------
# Finding formatters
# ---------------------------------------------------------------------------


def _format_finding_detail(finding: Finding, label: str) -> str:
    """Format a single finding with full details for the report."""
    parts: list[str] = []

    parts.append(f"### [{label}] {finding.title}\n")
    parts.append(f"**Location:** `{finding.location}`  ")
    if finding.swc:
        parts.append(
            f"**SWC:** [{finding.swc}](https://swcregistry.io/docs/{finding.swc})"
        )
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

    parts.append("---\n")
    return "\n".join(parts)


def _format_finding_line(finding: Finding) -> str:
    """One-line summary for low / informational findings."""
    return f"- **{finding.title}** — `{finding.location}`"


# ---------------------------------------------------------------------------
# Full report (saved to file + artifact)
# ---------------------------------------------------------------------------


def generate_report(report: AuditReport, config: dict) -> str:
    """Generate the full markdown audit report."""
    today = datetime.now().strftime("%B %d, %Y")
    s: list[str] = []

    # Header
    s.append("# Smart Contract Security Audit Report\n")
    s.append(f"**Generated:** {today}\n")

    # Summary table
    s.append("## Summary\n")
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
    s.append("*Generated by [sc4n3r](https://sc4n3r.app)*")
    return "\n".join(s)


# ---------------------------------------------------------------------------
# PR comment (posted to GitHub)
# ---------------------------------------------------------------------------


def generate_pr_comment(report: AuditReport, config: dict) -> str:
    """Generate a detailed PR comment with findings."""
    s: list[str] = []

    s.append("## 🔒 Security Audit Report\n")

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
    s.append("*Powered by [sc4n3r](https://sc4n3r.app)*")
    return "\n".join(s)


# ---------------------------------------------------------------------------
# Terminal report (printed to stdout)
# ---------------------------------------------------------------------------


def generate_terminal_report(report: AuditReport, config: dict) -> str:
    """Generate a clean, terminal-friendly audit report."""
    s: list[str] = []

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
