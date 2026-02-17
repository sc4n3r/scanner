"""
sc4n3r — OWASP Smart Contract Top 10 & SWC Mapping
Maps scanner findings to industry standards for professional-grade reporting.
"""

from .models import Finding


# ---------------------------------------------------------------------------
# OWASP Smart Contract Top 10 (2025)
# ---------------------------------------------------------------------------

OWASP_SC_TOP_10 = {
    "SC01": "Access Control Vulnerabilities",
    "SC02": "Business Logic Vulnerabilities",
    "SC03": "Price Oracle Manipulation",
    "SC04": "Flash Loan-Facilitated Attacks",
    "SC05": "Lack of Input Validation",
    "SC06": "Unchecked External Calls",
    "SC07": "Arithmetic Errors",
    "SC08": "Reentrancy Attacks",
    "SC09": "Integer Overflow and Underflow",
    "SC10": "Proxy & Upgradeability Vulnerabilities",
}

# ---------------------------------------------------------------------------
# Detector → OWASP mapping
# Maps tool detector IDs to OWASP categories
# ---------------------------------------------------------------------------

DETECTOR_TO_OWASP: dict[str, str] = {
    # SC01 — Access Control
    "unprotected-upgrade": "SC01",
    "suicidal": "SC01",
    "protected-vars": "SC01",
    "missing-authorization": "SC01",
    "tx-origin": "SC01",
    "ownership": "SC01",
    "access-control": "SC01",
    "uninitialized-state": "SC01",
    "default-visibility": "SC01",
    "incorrect-modifier": "SC01",
    "missing-zero-check": "SC01",
    "centralization-risk": "SC01",
    "no-auth-check": "SC01",

    # SC02 — Business Logic
    "incorrect-equality": "SC02",
    "tautology": "SC02",
    "boolean-cst": "SC02",
    "incorrect-using-for": "SC02",

    # SC03 — Oracle Manipulation
    "oracle-manipulation": "SC03",
    "price-manipulation": "SC03",
    "spot-price-usage": "SC03",
    "chainlink-price-stale": "SC03",

    # SC04 — Flash Loan
    "flash-loan": "SC04",

    # SC05 — Input Validation
    "missing-zero-address-validation": "SC05",
    "assert-state-change": "SC05",
    "input-validation": "SC05",
    "unchecked-param": "SC05",

    # SC06 — Unchecked External Calls
    "unchecked-call": "SC06",
    "unchecked-lowlevel": "SC06",
    "unchecked-send": "SC06",
    "unused-return": "SC06",
    "unchecked-transfer": "SC06",
    "low-level-calls": "SC06",
    "calls-loop": "SC06",
    "external-calls": "SC06",

    # SC07 — Arithmetic
    "divide-before-multiply": "SC07",
    "unchecked-math": "SC07",
    "precision-loss": "SC07",
    "arithmetic": "SC07",
    "rounding-error": "SC07",

    # SC08 — Reentrancy
    "reentrancy-eth": "SC08",
    "reentrancy-no-eth": "SC08",
    "reentrancy-benign": "SC08",
    "reentrancy-events": "SC08",
    "reentrancy-unlimited-gas": "SC08",
    "reentrancy": "SC08",
    "read-only-reentrancy": "SC08",
    "cross-contract-reentrancy": "SC08",

    # SC09 — Integer Overflow/Underflow
    "integer-overflow": "SC09",
    "integer-underflow": "SC09",

    # SC10 — Proxy & Upgradeability
    "delegatecall-loop": "SC10",
    "controlled-delegatecall": "SC10",
    "storage-collision": "SC10",
    "uninitialized-proxy": "SC10",
    "upgrade-vulnerability": "SC10",
    "proxy-vulnerability": "SC10",
    "delegatecall-to-untrusted-callee": "SC10",
}

# ---------------------------------------------------------------------------
# SWC Mapping (SWC Registry)
# Maps detector IDs to SWC IDs
# ---------------------------------------------------------------------------

DETECTOR_TO_SWC: dict[str, str] = {
    # SWC-100: Function Default Visibility
    "default-visibility": "SWC-100",
    "function-default-visibility": "SWC-100",

    # SWC-101: Integer Overflow and Underflow
    "integer-overflow": "SWC-101",
    "integer-underflow": "SWC-101",

    # SWC-104: Unchecked Call Return Value
    "unchecked-call": "SWC-104",
    "unchecked-lowlevel": "SWC-104",
    "unchecked-send": "SWC-104",
    "unused-return": "SWC-104",

    # SWC-105: Unprotected Ether Withdrawal
    "suicidal": "SWC-105",
    "unprotected-upgrade": "SWC-105",

    # SWC-106: Unprotected SELFDESTRUCT
    "suicidal": "SWC-106",

    # SWC-107: Reentrancy
    "reentrancy-eth": "SWC-107",
    "reentrancy-no-eth": "SWC-107",
    "reentrancy-benign": "SWC-107",
    "reentrancy-events": "SWC-107",
    "reentrancy-unlimited-gas": "SWC-107",
    "reentrancy": "SWC-107",

    # SWC-110: Assert Violation
    "assert-state-change": "SWC-110",

    # SWC-112: Delegatecall to Untrusted Callee
    "controlled-delegatecall": "SWC-112",
    "delegatecall-to-untrusted-callee": "SWC-112",
    "delegatecall-loop": "SWC-112",

    # SWC-113: DoS with Failed Call
    "calls-loop": "SWC-113",

    # SWC-114: Transaction Order Dependence
    "tx-origin": "SWC-115",

    # SWC-115: Authorization through tx.origin
    "tx-origin": "SWC-115",

    # SWC-116: Block values as a proxy for time
    "timestamp": "SWC-116",
    "block-timestamp": "SWC-116",
    "weak-prng": "SWC-120",

    # SWC-120: Weak Sources of Randomness
    "weak-prng": "SWC-120",

    # SWC-124: Write to Arbitrary Storage Location
    "storage-collision": "SWC-124",
}


# ---------------------------------------------------------------------------
# Keyword-based fallback matching
# ---------------------------------------------------------------------------

KEYWORD_TO_OWASP: list[tuple[list[str], str]] = [
    (["access", "control", "owner", "admin", "auth", "permission", "role"], "SC01"),
    (["logic", "business", "invariant", "state machine"], "SC02"),
    (["oracle", "price feed", "chainlink", "twap", "price"], "SC03"),
    (["flash loan", "flashloan", "flash"], "SC04"),
    (["input", "validation", "zero address", "parameter", "require"], "SC05"),
    (["unchecked", "external call", "low-level", "call.value"], "SC06"),
    (["arithmetic", "divide", "multiply", "precision", "rounding"], "SC07"),
    (["reentrancy", "reentrant", "re-entrant", "re-entrancy"], "SC08"),
    (["overflow", "underflow"], "SC09"),
    (["proxy", "upgrade", "delegatecall", "storage collision", "initializ"], "SC10"),
]


def _match_owasp_by_keywords(finding: Finding) -> str:
    """Fallback: match OWASP category by keywords in title/description/id."""
    text = f"{finding.id} {finding.title} {finding.description}".lower()
    for keywords, owasp in KEYWORD_TO_OWASP:
        if any(kw in text for kw in keywords):
            return owasp
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def map_finding_to_standards(finding: Finding) -> None:
    """Map a finding to OWASP SC Top 10 and SWC. Mutates in-place."""
    detector = finding.id.lower().strip()

    # OWASP mapping: try exact match first, then keywords
    owasp = DETECTOR_TO_OWASP.get(detector, "")
    if not owasp:
        owasp = _match_owasp_by_keywords(finding)
    if owasp:
        finding.owasp_category = owasp
        finding.owasp_title = OWASP_SC_TOP_10.get(owasp, "")

    # SWC mapping: exact match or use tool-reported SWC
    swc = DETECTOR_TO_SWC.get(detector, "")
    if swc:
        finding.swc_id = swc
    elif finding.swc:
        finding.swc_id = finding.swc


def map_all_findings(findings: list[Finding]) -> list[Finding]:
    """Map all findings to standards. Mutates in-place and returns."""
    for f in findings:
        map_finding_to_standards(f)
    return findings


def get_owasp_coverage(findings: list[Finding]) -> dict[str, dict]:
    """Build OWASP coverage matrix: which categories were checked and found."""
    coverage: dict[str, dict] = {}
    for code, title in OWASP_SC_TOP_10.items():
        matches = [f for f in findings if f.owasp_category == code and not f.is_false_positive]
        coverage[code] = {
            "title": title,
            "checked": True,
            "finding_count": len(matches),
            "highest_severity": max((f.severity_rank for f in matches), default=0),
        }
    return coverage
