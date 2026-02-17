"""
sc4n3r — DeFi-Specific Security Analysis
Detects flash loan susceptibility, oracle manipulation risk, MEV exposure,
and advanced reentrancy patterns by analyzing Solidity source code.
"""

import logging
import re
from pathlib import Path

from .models import Finding

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Oracle manipulation indicators
SPOT_PRICE_PATTERNS = [
    (r"\bgetReserves\b", "Uses getReserves() — vulnerable to spot price manipulation"),
    (r"\bbalanceOf\b.*\b(?:pair|pool|reserve)\b", "Reads pool balance for pricing — manipulable via flash loan"),
    (r"price\s*=\s*[^;]*(?:reserve|balance)", "Derives price from reserves/balances — use TWAP instead"),
    (r"\bslot0\b", "Uses Uniswap V3 slot0 — vulnerable to single-block manipulation"),
]

MISSING_ORACLE_CHECKS = [
    (r"latestRoundData\(\)", r"(?:require|assert|if)\s*\([^)]*(?:updatedAt|answeredInRound|timestamp)", "stale-oracle-data",
     "Chainlink latestRoundData() used without staleness check"),
    (r"latestAnswer\(\)", None, "deprecated-oracle",
     "Uses deprecated latestAnswer() — use latestRoundData() with validation"),
]

# Flash loan susceptibility
FLASH_LOAN_PATTERNS = [
    (r"(?:balanceOf|getReserves|totalSupply)\b[^;]*\n[^;]*(?:price|rate|ratio|exchange)",
     "Computes price/rate from live balances — flash loan manipulable"),
    (r"\bflashLoan\b|\bflash\b.*\bloan\b|\bIFlashLoan",
     "Implements or interacts with flash loan interface"),
]

# MEV exposure
MEV_PATTERNS = [
    (r"block\.timestamp\s*[<>=]", "Uses block.timestamp for critical logic — susceptible to miner manipulation"),
    (r"block\.number\s*[<>=]", "Uses block.number for time-dependent logic"),
    (r"(?:swap|trade|exchange)\b[^}]*\bslippage\b[^}]*0\b", "Potential zero slippage tolerance"),
]

# Missing slippage protection
SLIPPAGE_PATTERNS = [
    (r"(?:swap|trade)\b(?:(?!(?:minAmount|slippage|deadline|amountOutMin)).)*;",
     "Swap/trade without slippage protection parameter"),
]

# Read-only reentrancy
READ_ONLY_REENTRANCY = [
    (r"view\b[^{]*\{[^}]*(?:balanceOf|totalSupply|getReserves|slot0)",
     "View function reads state that may be stale during reentrancy"),
]


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------


def _scan_file(file_path: str, content: str) -> list[Finding]:
    """Scan a single file for DeFi-specific vulnerabilities."""
    findings: list[Finding] = []
    lines = content.splitlines()

    # --- Oracle manipulation ---
    for pattern, desc in SPOT_PRICE_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    id="spot-price-usage",
                    title="Spot Price Dependency",
                    severity="high",
                    file=file_path,
                    line=i,
                    tool="sc4n3r-defi",
                    description=desc,
                    source_module="defi",
                ))

    # --- Chainlink oracle staleness ---
    for call_pat, check_pat, det_id, desc in MISSING_ORACLE_CHECKS:
        for i, line in enumerate(lines, 1):
            if re.search(call_pat, line):
                if check_pat:
                    # Look in surrounding 10 lines for the check
                    context = "\n".join(lines[max(0, i - 5):min(len(lines), i + 5)])
                    if re.search(check_pat, context, re.IGNORECASE):
                        continue
                findings.append(Finding(
                    id=det_id,
                    title="Oracle Data Validation Missing",
                    severity="high" if det_id == "stale-oracle-data" else "medium",
                    file=file_path,
                    line=i,
                    tool="sc4n3r-defi",
                    description=desc,
                    source_module="defi",
                ))

    # --- Flash loan susceptibility ---
    for pattern, desc in FLASH_LOAN_PATTERNS:
        matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
        for m in matches:
            line_num = content[:m.start()].count("\n") + 1
            findings.append(Finding(
                id="flash-loan-susceptibility",
                title="Flash Loan Attack Surface",
                severity="medium",
                file=file_path,
                line=line_num,
                tool="sc4n3r-defi",
                description=desc,
                source_module="defi",
            ))

    # --- MEV exposure ---
    for pattern, desc in MEV_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    id="mev-exposure",
                    title="MEV / Transaction Ordering Risk",
                    severity="low",
                    file=file_path,
                    line=i,
                    tool="sc4n3r-defi",
                    description=desc,
                    source_module="defi",
                ))

    # --- Missing slippage protection ---
    for pattern, desc in SLIPPAGE_PATTERNS:
        matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
        for m in matches:
            line_num = content[:m.start()].count("\n") + 1
            findings.append(Finding(
                id="missing-slippage-protection",
                title="Missing Slippage Protection",
                severity="high",
                file=file_path,
                line=line_num,
                tool="sc4n3r-defi",
                description=desc,
                source_module="defi",
            ))

    # --- Missing deadline in swap ---
    if re.search(r"\bswap\b", content, re.IGNORECASE):
        if not re.search(r"\bdeadline\b|\bexpiry\b|\bexpiration\b", content, re.IGNORECASE):
            # Find the first swap function
            for i, line in enumerate(lines, 1):
                if re.search(r"\bswap\b", line, re.IGNORECASE):
                    findings.append(Finding(
                        id="missing-deadline",
                        title="Missing Transaction Deadline",
                        severity="medium",
                        file=file_path,
                        line=i,
                        tool="sc4n3r-defi",
                        description="Swap function without deadline parameter — transactions can be held and executed at unfavorable prices",
                        source_module="defi",
                    ))
                    break

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_defi(config: dict) -> list[Finding]:
    """Run DeFi-specific analysis on all Solidity files in scope."""
    contracts_path = config.get("contracts", {}).get("path", "src/")
    exclude_paths = config.get("contracts", {}).get("exclude_paths", [])

    all_findings: list[Finding] = []
    sol_files = sorted(Path(contracts_path).rglob("*.sol"))

    for sol in sol_files:
        rel = str(sol)
        if any(excl in rel for excl in exclude_paths):
            continue
        try:
            content = sol.read_text(encoding="utf-8", errors="ignore")
            findings = _scan_file(rel, content)
            all_findings.extend(findings)
        except (IOError, OSError) as e:
            log.warning(f"DeFi analyzer: could not read {rel}: {e}")

    log.info(f"DeFi analysis: {len(all_findings)} finding(s)")
    return all_findings
