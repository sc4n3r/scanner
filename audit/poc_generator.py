"""
sc4n3r — AI-Powered Proof of Concept Generator
Generates executable Foundry test PoCs for critical and high-severity findings.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

import requests

from .models import Finding

log = logging.getLogger(__name__)

GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)
CLAUDE_URL = "https://api.anthropic.com/v1/messages"


def _read_source(file_path: str) -> str:
    """Read the full source file."""
    try:
        return Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except (IOError, OSError):
        return "// Source file not found"


def _query_ai(prompt: str, api_key: str, provider: str, model: str, timeout: int) -> Optional[str]:
    """Route to AI provider with higher token limit for PoC generation."""
    if provider == "claude":
        try:
            resp = requests.post(
                CLAUDE_URL,
                json={"model": model, "max_tokens": 4096, "messages": [{"role": "user", "content": prompt}]},
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                return resp.json()["content"][0]["text"]
        except (requests.RequestException, KeyError, IndexError) as e:
            log.warning(f"PoC AI error: {e}")
        return None

    url = f"{GEMINI_URL.format(model=model)}?key={api_key}"
    try:
        resp = requests.post(
            url,
            json={"contents": [{"parts": [{"text": prompt}]}]},
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    except (requests.RequestException, KeyError, IndexError) as e:
        log.warning(f"PoC AI error: {e}")
    return None


def _extract_code(response: str) -> str:
    """Extract Solidity code from AI response."""
    # Try to find code block
    m = re.search(r"```(?:solidity)?\s*\n(.*?)```", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    # Fallback: entire response if it looks like code
    if "function" in response and "pragma" in response:
        return response.strip()
    return ""


def generate_poc(finding: Finding, config: dict) -> str:
    """Generate a Foundry test PoC for a single finding."""
    ai = config.get("ai", {})
    provider = ai.get("provider", "gemini").lower()

    from .ai_enhancer import PROVIDER_DEFAULTS
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["gemini"])

    api_key = os.environ.get(defaults["env"], "")
    if not api_key:
        return ""

    model = ai.get("model", defaults["model"])
    timeout = ai.get("timeout", 90) + 30  # Extra time for PoC generation

    source = _read_source(finding.file)

    # Query Solodit for similar findings with PoC examples
    solodit_context = ""
    try:
        from .solodit_client import get_similar_findings, format_as_context
        similar = get_similar_findings(
            finding_title=finding.title,
            severity=finding.severity,
            max_results=2,
        )
        if similar:
            solodit_context = "\n" + format_as_context(similar) + "\n"
    except Exception:
        pass

    prompt = f"""You are an expert smart contract security researcher. Generate an executable Foundry test that demonstrates this vulnerability as a Proof of Concept.
{solodit_context}

## Vulnerability
- **Title:** {finding.title}
- **Severity:** {finding.severity}
- **File:** {finding.file}
- **Line:** {finding.line}
- **Detector:** {finding.id}
- **Description:** {finding.description}
{f'- **Attack Scenario:** {finding.attack_scenario}' if finding.attack_scenario and finding.attack_scenario != 'N/A' else ''}
{f'- **Impact:** {finding.impact}' if finding.impact and finding.impact != 'N/A' else ''}

## Source Code
```solidity
{source[:3000]}
```

## Requirements
Generate a complete, compilable Foundry test file that:
1. Imports the vulnerable contract
2. Sets up the necessary state (deploy contracts, fund accounts, etc.)
3. Demonstrates the exploit step by step
4. Uses assertions to prove the exploit succeeded
5. Includes clear comments explaining each step

Use this template:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "{{path to vulnerable contract}}";

contract PoCTest is Test {{
    // State variables

    function setUp() public {{
        // Deploy and setup
    }}

    function test_exploit() public {{
        // Step-by-step exploitation
        // Assert the exploit succeeded
    }}
}}
```

Generate ONLY the Solidity test file code. No explanations outside the code."""

    log.info(f"  Generating PoC for: {finding.title[:50]}")
    resp = _query_ai(prompt, api_key, provider, model, timeout)
    if not resp:
        return ""

    code = _extract_code(resp)
    return code


def generate_pocs(findings: list[Finding], config: dict) -> list[Finding]:
    """Generate PoCs for critical and high-severity findings. Mutates in-place."""
    ai = config.get("ai", {})
    if not ai.get("enabled", False):
        return findings

    provider = ai.get("provider", "gemini").lower()
    from .ai_enhancer import PROVIDER_DEFAULTS
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["gemini"])

    api_key = os.environ.get(defaults["env"], "")
    if not api_key:
        return findings

    # Only generate PoCs for confirmed critical/high findings
    targets = [
        f for f in findings
        if f.severity.lower() in ("critical", "high")
        and not f.is_false_positive
        and f.ai_analyzed
    ][:5]  # Limit to 5 PoCs

    if not targets:
        log.info("PoC: no critical/high findings to generate PoCs for")
        return findings

    log.info(f"PoC: generating for {len(targets)} finding(s)")
    poc_dir = Path("results/pocs")
    poc_dir.mkdir(parents=True, exist_ok=True)

    for i, finding in enumerate(targets, 1):
        log.info(f"  [{i}/{len(targets)}] {finding.title[:60]}")
        poc_code = generate_poc(finding, config)
        if poc_code:
            finding.poc_code = poc_code
            # Save PoC to file
            safe_name = re.sub(r"[^a-zA-Z0-9]", "_", finding.title[:40])
            poc_path = poc_dir / f"PoC_{safe_name}.t.sol"
            poc_path.write_text(poc_code, encoding="utf-8")
            log.info(f"  Saved: {poc_path}")

    generated = sum(1 for f in findings if f.poc_code)
    log.info(f"PoC: {generated} generated")
    return findings
