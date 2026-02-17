"""
sc4n3r — Token Standard Compliance Checks
Verifies ERC-20, ERC-721, ERC-1155, and ERC-4626 compliance and detects
common token implementation vulnerabilities.
"""

import logging
import re
from pathlib import Path

from .models import Finding

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ERC detection
# ---------------------------------------------------------------------------


def _detect_token_type(content: str) -> list[str]:
    """Detect which token standards a file implements."""
    types = []
    if re.search(r"\bIERC20\b|\bERC20\b|function\s+transfer\s*\(\s*address", content):
        types.append("ERC20")
    if re.search(r"\bIERC721\b|\bERC721\b|function\s+safeTransferFrom\b", content):
        types.append("ERC721")
    if re.search(r"\bIERC1155\b|\bERC1155\b|function\s+safeBatchTransferFrom\b", content):
        types.append("ERC1155")
    if re.search(r"\bIERC4626\b|\bERC4626\b|function\s+(?:deposit|redeem|convertToShares)\b", content):
        types.append("ERC4626")
    return types


# ---------------------------------------------------------------------------
# ERC-20 checks
# ---------------------------------------------------------------------------


def _check_erc20(file_path: str, content: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    # Missing return value on transfer/transferFrom
    for func in ("transfer", "transferFrom", "approve"):
        pattern = rf"function\s+{func}\s*\([^)]*\)\s*(?:external|public)[^{{]*\{{"
        matches = list(re.finditer(pattern, content, re.MULTILINE))
        for m in matches:
            line_num = content[:m.start()].count("\n") + 1
            # Check if function returns bool
            func_sig = m.group()
            if "returns" not in func_sig and "bool" not in func_sig:
                # Look ahead for returns
                ahead = content[m.start():m.start() + 200]
                if "returns" not in ahead or "bool" not in ahead:
                    findings.append(Finding(
                        id="erc20-missing-return",
                        title=f"ERC-20: {func}() Missing bool Return",
                        severity="medium",
                        file=file_path,
                        line=line_num,
                        tool="sc4n3r-token",
                        description=f"{func}() should return bool per ERC-20 spec. Non-compliant tokens cause reverts in contracts that check return values.",
                        source_module="token",
                    ))

    # Approval race condition (missing allowance reset check)
    if re.search(r"function\s+approve\b", content):
        if not re.search(r"increaseAllowance|decreaseAllowance|safeApprove|safeIncreaseAllowance", content):
            for i, line in enumerate(lines, 1):
                if re.search(r"function\s+approve\b", line):
                    findings.append(Finding(
                        id="erc20-approval-race",
                        title="ERC-20: Approval Race Condition",
                        severity="low",
                        file=file_path,
                        line=i,
                        tool="sc4n3r-token",
                        description="Uses approve() without increaseAllowance/decreaseAllowance. The well-known approval race condition allows a spender to spend both the old and new allowance.",
                        source_module="token",
                    ))
                    break

    # Missing Transfer event
    if re.search(r"function\s+(?:transfer|transferFrom)\b", content):
        if not re.search(r"\bevent\s+Transfer\b|\bTransfer\(", content):
            findings.append(Finding(
                id="erc20-missing-transfer-event",
                title="ERC-20: Missing Transfer Event",
                severity="medium",
                file=file_path,
                line=1,
                tool="sc4n3r-token",
                description="Token has transfer functions but no Transfer event. ERC-20 requires emitting Transfer on every token movement.",
                source_module="token",
            ))

    # Missing zero-address check in transfer
    for func in ("transfer", "transferFrom"):
        pattern = rf"function\s+{func}\s*\("
        if re.search(pattern, content):
            # Find function body and check for zero-address check
            match = re.search(pattern, content)
            if match:
                body_start = content.find("{", match.start())
                if body_start != -1:
                    # Look at first 200 chars of function body
                    body = content[body_start:body_start + 300]
                    if not re.search(r"address\(0\)|address\(0x0\)|!= 0x0|!= address\(0\)", body):
                        line_num = content[:match.start()].count("\n") + 1
                        findings.append(Finding(
                            id="erc20-no-zero-check",
                            title=f"ERC-20: {func}() No Zero-Address Check",
                            severity="low",
                            file=file_path,
                            line=line_num,
                            tool="sc4n3r-token",
                            description=f"{func}() does not check for zero address. Tokens can be burned by accident.",
                            source_module="token",
                        ))

    return findings


# ---------------------------------------------------------------------------
# ERC-721 checks
# ---------------------------------------------------------------------------


def _check_erc721(file_path: str, content: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    # Missing onERC721Received check in transfer
    if re.search(r"function\s+transferFrom\b", content):
        if not re.search(r"\bsafeTransferFrom\b", content):
            for i, line in enumerate(lines, 1):
                if re.search(r"function\s+transferFrom\b", line):
                    findings.append(Finding(
                        id="erc721-unsafe-transfer",
                        title="ERC-721: Only transferFrom Without safeTransferFrom",
                        severity="medium",
                        file=file_path,
                        line=i,
                        tool="sc4n3r-token",
                        description="Contract has transferFrom but not safeTransferFrom. ERC-721 requires safeTransferFrom which checks if receiver can handle NFTs.",
                        source_module="token",
                    ))
                    break

    # Missing supportsInterface (ERC-165)
    if re.search(r"\bERC721\b|\bIERC721\b", content):
        if not re.search(r"\bsupportsInterface\b|\bERC165\b", content):
            findings.append(Finding(
                id="erc721-no-erc165",
                title="ERC-721: Missing ERC-165 Interface Detection",
                severity="low",
                file=file_path,
                line=1,
                tool="sc4n3r-token",
                description="ERC-721 token does not implement ERC-165 supportsInterface(). Other contracts cannot detect token type.",
                source_module="token",
            ))

    return findings


# ---------------------------------------------------------------------------
# ERC-4626 checks
# ---------------------------------------------------------------------------


def _check_erc4626(file_path: str, content: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []

    # Inflation / donation attack on empty vault
    if re.search(r"\bERC4626\b|\bIERC4626\b", content):
        has_virtual_offset = re.search(r"_decimalsOffset|virtualAssets|virtualShares|1e\d+\s*\+", content)
        if not has_virtual_offset:
            for i, line in enumerate(lines, 1):
                if re.search(r"\bERC4626\b|\bIERC4626\b", line):
                    findings.append(Finding(
                        id="erc4626-inflation-attack",
                        title="ERC-4626: Inflation / Donation Attack",
                        severity="high",
                        file=file_path,
                        line=i,
                        tool="sc4n3r-token",
                        description="ERC-4626 vault without virtual offset protection. An attacker can donate assets to an empty vault to inflate share price, stealing from subsequent depositors. Use OpenZeppelin's _decimalsOffset() or add virtual shares.",
                        source_module="token",
                    ))
                    break

    # Missing rounding direction check
    if re.search(r"function\s+(?:convertToShares|convertToAssets|previewDeposit|previewRedeem)\b", content):
        if not re.search(r"Math\.Rounding|mulDiv\w*\(.*(?:Ceil|Floor|Up|Down)", content):
            for i, line in enumerate(lines, 1):
                if re.search(r"function\s+(?:convertToShares|convertToAssets)\b", line):
                    findings.append(Finding(
                        id="erc4626-rounding",
                        title="ERC-4626: Rounding Direction Not Enforced",
                        severity="medium",
                        file=file_path,
                        line=i,
                        tool="sc4n3r-token",
                        description="ERC-4626 vault does not explicitly control rounding direction. convertToShares should round down (favoring vault), convertToAssets should round up (favoring vault).",
                        source_module="token",
                    ))
                    break

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _scan_file(file_path: str, content: str) -> list[Finding]:
    """Scan a single file for token compliance issues."""
    token_types = _detect_token_type(content)
    if not token_types:
        return []

    findings: list[Finding] = []
    lines = content.splitlines()

    if "ERC20" in token_types:
        findings.extend(_check_erc20(file_path, content, lines))
    if "ERC721" in token_types:
        findings.extend(_check_erc721(file_path, content, lines))
    if "ERC4626" in token_types:
        findings.extend(_check_erc4626(file_path, content, lines))

    return findings


def analyze_tokens(config: dict) -> list[Finding]:
    """Run token standard compliance analysis on all Solidity files in scope."""
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
            log.warning(f"Token analyzer: could not read {rel}: {e}")

    log.info(f"Token compliance analysis: {len(all_findings)} finding(s)")
    return all_findings
