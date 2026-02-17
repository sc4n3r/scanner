"""
sc4n3r — Centralization Risk Detection
Identifies single-owner patterns, missing timelocks, admin key risks,
and other centralization defects in Solidity contracts.
"""

import logging
import re
from pathlib import Path

from .models import Finding

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Admin functions without timelock
PRIVILEGED_FUNCTIONS = [
    r"function\s+(?:set|update|change|modify)\w*\s*\([^)]*\)\s*(?:external|public)\s+(?:onlyOwner|onlyRole|onlyAdmin)",
    r"function\s+(?:pause|unpause|freeze|blacklist|whitelist)\s*\([^)]*\)\s*(?:external|public)\s+(?:onlyOwner|onlyRole|onlyAdmin)",
    r"function\s+(?:mint|burn|withdraw|drain|sweep)\s*\([^)]*\)\s*(?:external|public)\s+(?:onlyOwner|onlyRole|onlyAdmin)",
    r"function\s+(?:upgrade|migrate|setImplementation)\s*\([^)]*\)\s*(?:external|public)\s+(?:onlyOwner|onlyRole|onlyAdmin)",
]

TIMELOCK_INDICATORS = [
    r"\btimelock\b",
    r"\bTimeLock\b",
    r"\bTimelockController\b",
    r"\bdelay\b.*\bblock\.timestamp\b",
    r"\bpendingAdmin\b",
    r"\btimelockDuration\b",
]

# Single-owner risks
SINGLE_OWNER_PATTERNS = [
    (r"\bOwnable\b(?!2Step)", "single-owner",
     "Uses Ownable without two-step transfer — ownership can be irrevocably lost if transferred to wrong address"),
    (r"address\s+(?:public\s+)?owner\b(?!.*mapping)", "custom-single-owner",
     "Custom single-owner pattern — consider multisig or governance"),
]

# Unconstrained privileged operations
UNCONSTRAINED_OPS = [
    (r"function\s+mint\s*\([^)]*\)\s*(?:external|public)\s+onlyOwner\b",
     r"\bmaxSupply\b|\bcap\b|\bMAX_SUPPLY\b",
     "unconstrained-mint", "Owner can mint unlimited tokens — no supply cap enforced"),
    (r"function\s+(?:pause|freeze)\s*\([^)]*\)\s*(?:external|public)\s+onlyOwner\b",
     r"\btimelock\b|\bTimeLock\b",
     "pause-without-timelock", "Owner can pause contract without timelock — potential rug vector"),
    (r"function\s+(?:withdraw|drain|sweep)\s*\([^)]*\)\s*(?:external|public)\s+onlyOwner\b",
     r"\btimelock\b|\bdelay\b",
     "owner-can-drain", "Owner can withdraw all funds — potential rug pull"),
]

# Missing renounceOwnership override
RENOUNCE_PATTERN = r"\brenounceOwnership\b"


def _scan_file(file_path: str, content: str) -> list[Finding]:
    """Scan a single file for centralization risks."""
    findings: list[Finding] = []
    lines = content.splitlines()

    # Check for timelock usage anywhere in the file
    has_timelock = any(
        re.search(p, content, re.IGNORECASE) for p in TIMELOCK_INDICATORS
    )

    # --- Privileged functions without timelock ---
    if not has_timelock:
        for pattern in PRIVILEGED_FUNCTIONS:
            matches = list(re.finditer(pattern, content, re.MULTILINE))
            for m in matches:
                line_num = content[:m.start()].count("\n") + 1
                func_name = re.search(r"function\s+(\w+)", m.group())
                name = func_name.group(1) if func_name else "unknown"
                findings.append(Finding(
                    id="privileged-no-timelock",
                    title=f"Privileged Function Without Timelock: {name}()",
                    severity="medium",
                    file=file_path,
                    line=line_num,
                    tool="sc4n3r-centralization",
                    description=f"Admin function {name}() can be called instantly without timelock delay. An compromised admin key could cause immediate damage.",
                    source_module="centralization",
                ))

    # --- Single-owner patterns ---
    for pattern, det_id, desc in SINGLE_OWNER_PATTERNS:
        matches = list(re.finditer(pattern, content))
        for m in matches:
            line_num = content[:m.start()].count("\n") + 1
            findings.append(Finding(
                id=det_id,
                title="Single-Owner Centralization Risk",
                severity="medium",
                file=file_path,
                line=line_num,
                tool="sc4n3r-centralization",
                description=desc,
                source_module="centralization",
            ))

    # --- Unconstrained privileged operations ---
    for func_pat, guard_pat, det_id, desc in UNCONSTRAINED_OPS:
        if re.search(func_pat, content, re.MULTILINE):
            if not re.search(guard_pat, content, re.IGNORECASE):
                match = re.search(func_pat, content, re.MULTILINE)
                if match:
                    line_num = content[:match.start()].count("\n") + 1
                    findings.append(Finding(
                        id=det_id,
                        title=desc.split(" — ")[0] if " — " in desc else desc[:60],
                        severity="high",
                        file=file_path,
                        line=line_num,
                        tool="sc4n3r-centralization",
                        description=desc,
                        source_module="centralization",
                    ))

    # --- Missing multisig for critical functions ---
    if re.search(r"\bonlyOwner\b", content):
        has_multisig = re.search(
            r"\bGnosis\b|\bSafe\b|\bmultisig\b|\bmultiSig\b|\bGnosisSafe\b",
            content, re.IGNORECASE,
        )
        if not has_multisig:
            # Report once per file
            for i, line in enumerate(lines, 1):
                if re.search(r"\bonlyOwner\b", line):
                    findings.append(Finding(
                        id="no-multisig",
                        title="No Multisig Requirement for Admin Functions",
                        severity="low",
                        file=file_path,
                        line=i,
                        tool="sc4n3r-centralization",
                        description="Contract uses onlyOwner but does not reference multisig patterns. Consider using a multisig wallet as the owner.",
                        source_module="centralization",
                    ))
                    break

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_centralization(config: dict) -> list[Finding]:
    """Run centralization risk analysis on all Solidity files in scope."""
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
            log.warning(f"Centralization analyzer: could not read {rel}: {e}")

    log.info(f"Centralization analysis: {len(all_findings)} finding(s)")
    return all_findings
