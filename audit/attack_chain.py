"""
sc4n3r — Cross-Finding Attack Chain Detection
Analyzes all findings together to identify how multiple vulnerabilities
can be combined into critical attack chains.
"""

import json
import logging
import os
import re
from typing import Optional

import requests

from .models import Finding

log = logging.getLogger(__name__)

GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)
CLAUDE_URL = "https://api.anthropic.com/v1/messages"


def _query_ai(prompt: str, api_key: str, provider: str, model: str, timeout: int) -> Optional[str]:
    """Route to AI provider."""
    if provider == "claude":
        try:
            resp = requests.post(
                CLAUDE_URL,
                json={"model": model, "max_tokens": 2048, "messages": [{"role": "user", "content": prompt}]},
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                return resp.json()["content"][0]["text"]
        except (requests.RequestException, KeyError, IndexError) as e:
            log.warning(f"Attack chain AI error: {e}")
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
        log.warning(f"Attack chain AI error: {e}")
    return None


def _parse_json_response(text: str) -> list:
    """Parse JSON array from AI response."""
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text)
    try:
        data = json.loads(text.strip())
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "chains" in data:
            return data["chains"]
        return [data] if isinstance(data, dict) else []
    except json.JSONDecodeError:
        return []


def detect_attack_chains(
    findings: list[Finding], config: dict,
) -> list[dict]:
    """
    Use AI to detect attack chains — combinations of findings that create
    higher-severity attack paths.

    Returns list of chain dicts:
    {
        "chain_id": "CHAIN-1",
        "title": "Oracle Manipulation via Flash Loan",
        "severity": "critical",
        "findings": ["F-1", "F-3", "F-7"],
        "attack_path": "1. Take flash loan...",
        "combined_impact": "Full protocol drain",
    }
    """
    ai = config.get("ai", {})
    if not ai.get("enabled", False):
        return []

    # Only analyze if there are enough findings to form chains
    confirmed = [f for f in findings if not f.is_false_positive]
    if len(confirmed) < 2:
        return []

    provider = ai.get("provider", "gemini").lower()
    from .ai_enhancer import PROVIDER_DEFAULTS
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["gemini"])

    api_key = os.environ.get(defaults["env"], "")
    if not api_key:
        return []

    model = ai.get("model", defaults["model"])
    timeout = ai.get("timeout", 90)

    # Build findings summary for the prompt
    findings_text = ""
    for i, f in enumerate(confirmed[:30], 1):
        findings_text += (
            f"F-{i}: [{f.severity.upper()}] {f.title} at {f.location} "
            f"(detector: {f.id}, tool: {f.tool})\n"
        )
        if f.description:
            findings_text += f"   Description: {f.description[:150]}\n"
        if f.attack_scenario and f.attack_scenario != "N/A":
            findings_text += f"   Attack: {f.attack_scenario[:150]}\n"

    prompt = f"""You are an expert smart contract security auditor. Below are individual findings from a security scan. Analyze them TOGETHER to identify attack chains — combinations of 2 or more findings that, when exploited together, create a higher-severity attack than any single finding alone.

## Individual Findings
{findings_text}

## Instructions
Look for:
1. Access control gaps that enable exploitation of other vulnerabilities
2. Oracle manipulation + flash loan combinations
3. Reentrancy + state inconsistency chains
4. Missing validation + privileged function combinations
5. Any sequence where exploiting finding A enables or amplifies finding B

If no meaningful chains exist, return an empty array.

Respond with ONLY valid JSON (no markdown fences):
[
  {{
    "chain_id": "CHAIN-1",
    "title": "<descriptive attack chain name>",
    "severity": "<critical|high|medium>",
    "findings": ["F-1", "F-3"],
    "attack_path": "<numbered step-by-step attack>",
    "combined_impact": "<what the attacker achieves>"
  }}
]"""

    log.info("Analyzing attack chains...")
    resp = _query_ai(prompt, api_key, provider, model, timeout)
    if not resp:
        return []

    chains = _parse_json_response(resp)

    # Tag findings with their chain IDs
    for chain in chains:
        chain_id = chain.get("chain_id", "")
        for ref in chain.get("findings", []):
            # Parse F-N reference
            m = re.match(r"F-(\d+)", ref)
            if m:
                idx = int(m.group(1)) - 1
                if 0 <= idx < len(confirmed):
                    confirmed[idx].chain_id = chain_id

    log.info(f"Attack chains: {len(chains)} detected")
    return chains
