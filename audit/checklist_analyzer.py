"""
sc4n3r — Checklist-Driven Analysis Engine
Uses Cyfrin's 380+ audit checklist to perform systematic security checks,
mirroring the methodology of professional audit firms.
"""

import json
import logging
import re
from pathlib import Path

from .models import Finding

log = logging.getLogger(__name__)

# Path to bundled checklist data
CHECKLIST_PATH = Path(__file__).parent / "data" / "checklist.json"

# ---------------------------------------------------------------------------
# Checklist item to automated check mapping
# ---------------------------------------------------------------------------

# Maps checklist item IDs to regex patterns that detect the issue.
# Each entry: (pattern_in_code, severity, description_override)
# These target the most impactful and automatable checks from the 380+ items.
AUTOMATED_CHECKS: dict[str, dict] = {
    # --- Denial of Service ---
    "SOL-AM-DOSA-1": {
        "patterns": [
            r"\.transfer\(",  # push-based transfers can DoS
            r"\.send\(",
        ],
        "severity": "medium",
        "match_context": "withdrawal",
        "negative_patterns": [],  # patterns that indicate the issue is handled
    },
    # --- Front-running ---
    "SOL-AM-FRA-1": {
        "patterns": [
            r"commit.*reveal|reveal.*commit",
        ],
        "severity": "medium",
        "match_context": "auction|bid|vote",
        "negative_patterns": [r"commitReveal|commit_reveal"],
    },
    # --- Reentrancy ---
    "SOL-AM-RA-1": {
        "patterns": [
            r"\.call\{value:",
            r"\.call\{.*value\s*:",
        ],
        "severity": "high",
        "match_context": "",
        "negative_patterns": [r"nonReentrant|reentrancyGuard|ReentrancyGuard"],
    },
    # --- Access Control ---
    "SOL-B-AC-1": {
        "patterns": [
            r"function\s+\w+\s*\([^)]*\)\s+(external|public)\s+(?!.*(?:onlyOwner|onlyRole|onlyAdmin|require\s*\(|_checkRole))",
        ],
        "severity": "medium",
        "match_context": "admin|owner|set|update|pause|mint|burn|withdraw",
        "negative_patterns": [],
    },
    # --- Initialization ---
    "SOL-B-I-1": {
        "patterns": [
            r"function\s+initialize\s*\(",
        ],
        "severity": "high",
        "match_context": "",
        "negative_patterns": [r"initializer\b|_disableInitializers"],
    },
    "SOL-B-I-2": {
        "patterns": [
            r"Initializable|UUPSUpgradeable|TransparentUpgradeable",
        ],
        "severity": "high",
        "match_context": "",
        "negative_patterns": [r"_disableInitializers\(\)"],
    },
    # --- Math ---
    "SOL-B-M-1": {
        "patterns": [
            r"\b\w+\s*/\s*\w+\s*\*",  # division before multiplication
        ],
        "severity": "medium",
        "match_context": "",
        "negative_patterns": [],
    },
    # --- Proxy / Upgradable ---
    "SOL-B-PU-1": {
        "patterns": [
            r"selfdestruct|delegatecall",
        ],
        "severity": "high",
        "match_context": "implementation|proxy|upgradeable",
        "negative_patterns": [],
    },
    "SOL-B-PU-3": {
        "patterns": [
            r"UUPSUpgradeable",
        ],
        "severity": "high",
        "match_context": "",
        "negative_patterns": [r"_authorizeUpgrade"],
    },
    # --- Payment ---
    "SOL-B-P-1": {
        "patterns": [
            r"msg\.value",
        ],
        "severity": "medium",
        "match_context": "loop|for\s*\(|while\s*\(",
        "negative_patterns": [],
    },
    # --- Price Manipulation ---
    "SOL-AM-PMA-1": {
        "patterns": [
            r"getReserves\(\)|balanceOf\(address\(this\)\)|\.reserve[01]\(",
        ],
        "severity": "high",
        "match_context": "price|swap|exchange|rate",
        "negative_patterns": [r"TWAP|twap|oracle|chainlink"],
    },
}


def load_checklist() -> list[dict]:
    """Load the bundled audit checklist."""
    if not CHECKLIST_PATH.exists():
        log.warning(f"Checklist not found: {CHECKLIST_PATH}")
        return []
    try:
        data = json.loads(CHECKLIST_PATH.read_text(encoding="utf-8"))
        # Flatten the nested category structure into a flat list of items
        # Structure: [{category, data: [{category, data: [{id, question, ...}]}]}]
        items = []
        if isinstance(data, list):
            for category in data:
                if not isinstance(category, dict):
                    continue
                for subcategory in category.get("data", category.get("children", [])):
                    if not isinstance(subcategory, dict):
                        continue
                    # Subcategory may have its own data array of items
                    for item in subcategory.get("data", subcategory.get("children", [])):
                        if isinstance(item, dict) and item.get("id"):
                            items.append(item)
                    # Or the subcategory itself may be an item
                    if subcategory.get("id"):
                        items.append(subcategory)
        log.info(f"Checklist: loaded {len(items)} items")
        return items
    except (json.JSONDecodeError, IOError) as e:
        log.warning(f"Checklist: parse error — {e}")
        return []


def _collect_sol_files(config: dict) -> list[Path]:
    """Collect Solidity files to analyze."""
    contracts_path = config.get("contracts", {}).get("path", "src/")
    exclude = config.get("contracts", {}).get("exclude_paths", [])
    base = Path(contracts_path)
    if not base.exists():
        return []

    files = []
    for sol in sorted(base.rglob("*.sol")):
        rel = str(sol)
        if any(ex in rel for ex in exclude):
            continue
        files.append(sol)
    return files


def _check_file(
    file_path: Path, content: str, check_id: str, check: dict,
) -> list[Finding]:
    """Run a single automated check against a file."""
    findings = []
    patterns = check.get("patterns", [])
    negative_patterns = check.get("negative_patterns", [])
    match_context = check.get("match_context", "")
    severity = check.get("severity", "medium")

    # If match_context is set, only check files whose content matches context
    if match_context and not re.search(match_context, content, re.IGNORECASE):
        return []

    for pattern in patterns:
        for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
            # Check if any negative pattern exists nearby (within 500 chars)
            start = max(0, match.start() - 500)
            end = min(len(content), match.end() + 500)
            context_window = content[start:end]

            is_mitigated = False
            for neg in negative_patterns:
                if re.search(neg, context_window, re.IGNORECASE):
                    is_mitigated = True
                    break

            if is_mitigated:
                continue

            # Calculate line number
            line_num = content[:match.start()].count("\n") + 1

            findings.append(Finding(
                id=f"checklist-{check_id}",
                title=f"Checklist {check_id}: potential issue detected",
                severity=severity,
                file=str(file_path),
                line=line_num,
                tool="sc4n3r-Checklist",
                description=f"Automated check {check_id} flagged this code pattern.",
                source_module="checklist",
            ))
            break  # One finding per check per file

    return findings


def analyze_checklist(config: dict) -> tuple[list[Finding], dict]:
    """Run checklist-driven analysis on the codebase.

    Returns:
        Tuple of (findings, coverage_report) where coverage_report maps
        checklist IDs to their status: "pass", "fail", or "not_applicable"
    """
    checklist = load_checklist()
    sol_files = _collect_sol_files(config)

    if not sol_files:
        log.info("Checklist: no Solidity files found")
        return [], {}

    # Read all file contents
    file_contents: dict[Path, str] = {}
    for f in sol_files:
        try:
            file_contents[f] = f.read_text(encoding="utf-8", errors="ignore")
        except (IOError, OSError):
            continue

    all_findings: list[Finding] = []
    coverage: dict[str, str] = {}

    # Run automated checks
    automated_count = 0
    for check_id, check in AUTOMATED_CHECKS.items():
        has_finding = False
        for file_path, content in file_contents.items():
            findings = _check_file(file_path, content, check_id, check)
            if findings:
                all_findings.extend(findings)
                has_finding = True
        coverage[check_id] = "fail" if has_finding else "pass"
        automated_count += 1

    # Mark remaining checklist items as not automated
    for item in checklist:
        item_id = item.get("id", "")
        if item_id and item_id not in coverage:
            coverage[item_id] = "manual_review"

    log.info(
        f"Checklist: {automated_count} automated checks, "
        f"{len(all_findings)} issue(s) found, "
        f"{len(checklist)} total items"
    )

    return all_findings, coverage


def generate_checklist_report(
    coverage: dict[str, str], checklist_items: list[dict],
) -> str:
    """Generate the checklist coverage section for the report."""
    if not coverage:
        return ""

    s: list[str] = []
    s.append("## Audit Checklist Coverage\n")
    s.append(
        f"*Evaluated {len(coverage)} of {len(checklist_items)} checklist items "
        f"from the [Cyfrin Audit Checklist](https://solodit.cyfrin.io/checklist).*\n"
    )

    automated = sum(1 for v in coverage.values() if v in ("pass", "fail"))
    passed = sum(1 for v in coverage.values() if v == "pass")
    failed = sum(1 for v in coverage.values() if v == "fail")
    manual = sum(1 for v in coverage.values() if v == "manual_review")

    s.append("| Status | Count |")
    s.append("|--------|-------|")
    s.append(f"| Automated Checks | {automated} |")
    s.append(f"| Passed | {passed} |")
    s.append(f"| Issues Found | {failed} |")
    s.append(f"| Requires Manual Review | {manual} |")
    s.append("")

    # Show failed checks with details
    if failed > 0:
        s.append("### Issues Detected\n")
        for check_id, status in sorted(coverage.items()):
            if status == "fail":
                # Find the checklist item for context
                item_data = next(
                    (i for i in checklist_items if i.get("id") == check_id),
                    {},
                )
                question = item_data.get("question", check_id)
                s.append(f"- **{check_id}**: {question}")
        s.append("")

    return "\n".join(s)
