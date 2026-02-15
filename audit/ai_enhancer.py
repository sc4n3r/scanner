"""
sc4n3r — AI Enhancement
Analyzes findings to detect false positives and provide actionable guidance.
Supports Gemini and Claude as AI providers.
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


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _read_code_context(file_path: str, line: int, context: int = 15) -> str:
    """Extract source code around a finding location."""
    try:
        path = Path(file_path)
        if not path.exists():
            return "// Source file not found"
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        result = []
        for i in range(start, end):
            marker = ">>> " if i == line - 1 else "    "
            result.append(f"{marker}{i + 1:4d} | {lines[i]}")
        return "\n".join(result)
    except (IOError, OSError):
        return "// Could not read source file"


def _query_gemini(
    prompt: str, api_key: str, model: str, timeout: int,
) -> Optional[str]:
    """Send a prompt to the Gemini API and return the text response."""
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
        log.warning(f"AI: {resp.status_code} | {resp.text[:300]}")
    except (requests.RequestException, KeyError, IndexError) as e:
        log.warning(f"AI error: {e}")
    return None


def _query_claude(
    prompt: str, api_key: str, model: str, timeout: int,
) -> Optional[str]:
    """Send a prompt to the Claude API and return the text response."""
    try:
        resp = requests.post(
            CLAUDE_URL,
            json={
                "model": model,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}],
            },
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json()["content"][0]["text"]
        log.warning(f"AI: {resp.status_code} | {resp.text[:300]}")
    except (requests.RequestException, KeyError, IndexError) as e:
        log.warning(f"AI error: {e}")
    return None


def _query_ai(
    prompt: str, api_key: str, provider: str, model: str, timeout: int,
) -> Optional[str]:
    """Route to the correct AI provider."""
    if provider == "claude":
        return _query_claude(prompt, api_key, model, timeout)
    return _query_gemini(prompt, api_key, model, timeout)


def _parse_json_response(text: str) -> dict:
    """Parse JSON from an AI response, stripping markdown code fences."""
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text)
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        return {}


def _analyze_finding(
    finding: Finding, api_key: str, provider: str, model: str, timeout: int,
) -> None:
    """Use AI to analyse a single finding. Mutates the Finding in-place."""
    code = _read_code_context(finding.file, finding.line)

    prompt = f"""You are a smart contract security auditor. Analyze this scanner finding.

## Finding
- **Tool:** {finding.tool}
- **Detector:** {finding.id}
- **Title:** {finding.title}
- **Severity:** {finding.severity}
- **Location:** {finding.file}:{finding.line}
- **Description:** {finding.description}

## Source Code
```solidity
{code}
```

Determine whether this is genuinely exploitable or a false positive.
Consider:
1. Can an attacker exploit this given the surrounding code?
2. Are there protections already in place (require, modifiers, access control)?
3. What is the realistic step-by-step attack scenario?
4. What is the maximum financial / protocol impact?

Respond with ONLY valid JSON (no markdown fences, no extra text):
{{
  "is_false_positive": <true or false>,
  "confidence": "<high|medium|low>",
  "reasoning": "<2-3 sentence explanation>",
  "attack_scenario": "<numbered steps if exploitable, 'N/A' if false positive>",
  "impact": "<specific impact, e.g. 'All ETH in the vault can be drained'>",
  "suggested_fix": "<diff-style code fix showing the change needed>"
}}"""

    resp = _query_ai(prompt, api_key, provider, model, timeout)
    if not resp:
        return

    data = _parse_json_response(resp)
    if not data:
        return

    finding.is_false_positive = data.get("is_false_positive", False)
    finding.ai_confidence = data.get("confidence", "low")
    finding.attack_scenario = data.get("attack_scenario", "")
    finding.impact = data.get("impact", "")
    finding.suggested_fix = data.get("suggested_fix", "")
    finding.ai_analyzed = True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

PROVIDER_DEFAULTS = {
    "gemini": {"model": "gemini-2.0-flash", "env": "GEMINI_API_KEY"},
    "claude": {"model": "claude-sonnet-4-5-20250929", "env": "ANTHROPIC_API_KEY"},
}


def enhance_findings(findings: list[Finding], config: dict) -> list[Finding]:
    """Enhance findings with AI analysis. Mutates findings in-place."""
    ai = config.get("ai", {})
    if not ai.get("enabled", False):
        log.info("AI: disabled")
        return findings

    provider = ai.get("provider", "gemini").lower()
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["gemini"])

    api_key = os.environ.get(defaults["env"], "")
    if not api_key:
        log.warning(f"AI: {defaults['env']} not set")
        return findings

    model = ai.get("model", defaults["model"])
    timeout = ai.get("timeout", 90)
    severities = [s.lower() for s in ai.get("analyze_only", ["critical", "high", "medium"])]
    max_count = ai.get("max_findings", 25)

    to_analyze = [f for f in findings if f.severity.lower() in severities][:max_count]
    if not to_analyze:
        log.info("AI: no findings at configured severities")
        return findings

    log.info(f"AI: analyzing {len(to_analyze)} finding(s)")
    for i, finding in enumerate(to_analyze, 1):
        log.info(f"  [{i}/{len(to_analyze)}] {finding.title[:60]}")
        _analyze_finding(finding, api_key, provider, model, timeout)

    analyzed = sum(1 for f in findings if f.ai_analyzed)
    fp = sum(1 for f in findings if f.is_false_positive)
    log.info(f"AI: {analyzed} analyzed, {fp} false positive(s)")
    return findings
