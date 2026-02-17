"""
sc4n3r — Proxy & Upgrade Safety Checks
Detects proxy patterns and common upgradeability vulnerabilities:
  - Storage layout collisions
  - Uninitialized implementation contracts
  - Missing _disableInitializers()
  - Selfdestruct in implementation
  - EIP-1967 compliance issues
"""

import logging
import re
from pathlib import Path

from .models import Finding

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Proxy pattern detection
# ---------------------------------------------------------------------------

PROXY_INDICATORS = [
    r"\bTransparentUpgradeableProxy\b",
    r"\bUUPSUpgradeable\b",
    r"\bERC1967Proxy\b",
    r"\bERC1967Upgrade\b",
    r"\bBeaconProxy\b",
    r"\bUpgradeableBeacon\b",
    r"\bDiamondCut\b",
    r"\bIDiamondCut\b",
    r"\bdelegatecall\b",
    r"\b_implementation\b",
    r"\bproxiableUUID\b",
    r"\b_upgradeTo\b",
    r"\bupgradeToAndCall\b",
    r"\bInitializable\b",
]


def _is_proxy_related(content: str) -> bool:
    """Check if a file contains proxy/upgrade patterns."""
    return any(re.search(p, content) for p in PROXY_INDICATORS)


def _scan_file(file_path: str, content: str) -> list[Finding]:
    """Scan a single file for upgrade safety issues."""
    findings: list[Finding] = []
    lines = content.splitlines()

    if not _is_proxy_related(content):
        return findings

    # --- Selfdestruct in implementation ---
    for i, line in enumerate(lines, 1):
        if re.search(r"\bselfdestruct\b|\bsuicide\b", line, re.IGNORECASE):
            findings.append(Finding(
                id="selfdestruct-in-implementation",
                title="Selfdestruct in Upgradeable Contract",
                severity="critical",
                file=file_path,
                line=i,
                tool="sc4n3r-upgrade",
                description="selfdestruct in an implementation contract can destroy the proxy's code, bricking the entire system permanently.",
                source_module="upgrade",
            ))

    # --- Delegatecall to user-controlled address ---
    for i, line in enumerate(lines, 1):
        if re.search(r"\.delegatecall\(", line):
            # Check if address comes from a parameter or storage
            context = "\n".join(lines[max(0, i - 5):min(len(lines), i + 2)])
            if not re.search(r"_implementation\(\)|ERC1967|_getImplementation|proxiableUUID", context):
                findings.append(Finding(
                    id="uncontrolled-delegatecall",
                    title="Delegatecall to Potentially Untrusted Address",
                    severity="high",
                    file=file_path,
                    line=i,
                    tool="sc4n3r-upgrade",
                    description="delegatecall target may not be a trusted implementation. Verify the target is from EIP-1967 storage slot or otherwise secured.",
                    source_module="upgrade",
                ))

    # --- Missing _disableInitializers in constructor ---
    is_initializable = bool(re.search(r"\bInitializable\b", content))
    has_initializer = bool(re.search(r"\binitializ(?:e|er)\b", content, re.IGNORECASE))

    if is_initializable or has_initializer:
        has_constructor = bool(re.search(r"\bconstructor\s*\(", content))
        has_disable = bool(re.search(r"_disableInitializers\(\)", content))

        if has_constructor and not has_disable:
            match = re.search(r"\bconstructor\s*\(", content)
            line_num = content[:match.start()].count("\n") + 1 if match else 1
            findings.append(Finding(
                id="missing-disable-initializers",
                title="Missing _disableInitializers() in Constructor",
                severity="high",
                file=file_path,
                line=line_num,
                tool="sc4n3r-upgrade",
                description="Implementation contract has a constructor but does not call _disableInitializers(). An attacker can initialize the implementation directly and potentially take ownership.",
                source_module="upgrade",
            ))

        if not has_constructor and not has_disable:
            # No constructor at all — initializer could be called on implementation
            findings.append(Finding(
                id="uninitialized-implementation",
                title="Implementation Contract May Be Uninitialized",
                severity="high",
                file=file_path,
                line=1,
                tool="sc4n3r-upgrade",
                description="Initializable contract without constructor or _disableInitializers(). The implementation can be initialized by anyone, potentially leading to takeover.",
                source_module="upgrade",
            ))

    # --- UUPS missing _authorizeUpgrade ---
    if re.search(r"\bUUPSUpgradeable\b", content):
        if not re.search(r"function\s+_authorizeUpgrade\b", content):
            findings.append(Finding(
                id="missing-authorize-upgrade",
                title="UUPS Missing _authorizeUpgrade Override",
                severity="critical",
                file=file_path,
                line=1,
                tool="sc4n3r-upgrade",
                description="UUPSUpgradeable contract does not override _authorizeUpgrade(). Anyone could upgrade the implementation to a malicious contract.",
                source_module="upgrade",
            ))

    # --- Storage gap missing in base contracts ---
    is_base = bool(re.search(r"\bis\s+\w+Upgradeable\b", content))
    if is_base and not re.search(r"__gap\b|uint256\[\d+\]\s+private\s+__", content):
        if re.search(r"(?:uint|int|address|bool|string|bytes|mapping)\s+(?:public|private|internal)\s+\w+", content):
            findings.append(Finding(
                id="missing-storage-gap",
                title="Missing Storage Gap in Upgradeable Base Contract",
                severity="medium",
                file=file_path,
                line=1,
                tool="sc4n3r-upgrade",
                description="Upgradeable base contract with state variables but no __gap. Adding new variables in future versions will cause storage collisions with derived contracts.",
                source_module="upgrade",
            ))

    # --- Initializer not protected ---
    init_matches = list(re.finditer(r"function\s+(initialize\w*)\s*\(", content))
    for m in init_matches:
        line_num = content[:m.start()].count("\n") + 1
        func_context = "\n".join(lines[line_num - 1:min(len(lines), line_num + 5)])
        if not re.search(r"\binitializer\b|\breinitializer\b", func_context):
            findings.append(Finding(
                id="unprotected-initializer",
                title=f"Initializer {m.group(1)}() Without Modifier",
                severity="critical",
                file=file_path,
                line=line_num,
                tool="sc4n3r-upgrade",
                description=f"Function {m.group(1)}() can be called multiple times — missing `initializer` or `reinitializer` modifier. An attacker could re-initialize the contract.",
                source_module="upgrade",
            ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_upgrades(config: dict) -> list[Finding]:
    """Run upgrade safety analysis on all Solidity files in scope."""
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
            log.warning(f"Upgrade analyzer: could not read {rel}: {e}")

    log.info(f"Upgrade safety analysis: {len(all_findings)} finding(s)")
    return all_findings
