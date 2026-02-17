"""
sc4n3r — Solodit API Client
Queries Solodit's 49K+ vulnerability database for real-world finding context.
Used to enrich AI analysis with actual audit findings as few-shot examples.
"""

import json
import logging
import os

import requests

log = logging.getLogger(__name__)

SOLODIT_API_BASE = "https://solodit.cyfrin.io/api/v1"
SOLODIT_SEARCH_URL = f"{SOLODIT_API_BASE}/findings"

# Cache to avoid repeated API calls for the same query within a single scan
_cache: dict[str, list[dict]] = {}


def _get_api_key() -> str:
    """Get Solodit API key from environment."""
    return os.environ.get("SOLODIT_API_KEY", "")


def search_findings(
    query: str,
    impact: str = "",
    max_results: int = 5,
    timeout: int = 15,
) -> list[dict]:
    """Search Solodit for findings matching a query.

    Args:
        query: Search keywords (e.g., "reentrancy withdraw ETH")
        impact: Filter by impact level ("High", "Medium", "Low")
        max_results: Maximum number of results to return
        timeout: Request timeout in seconds

    Returns:
        List of finding dicts with keys: title, impact, description, poc, mitigation
    """
    cache_key = f"{query}:{impact}:{max_results}"
    if cache_key in _cache:
        return _cache[cache_key]

    api_key = _get_api_key()
    if not api_key:
        log.debug("Solodit: no API key set (SOLODIT_API_KEY)")
        return []

    params: dict = {
        "q": query,
        "page_size": min(max_results, 10),
    }
    if impact:
        params["impact"] = impact

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }

    try:
        resp = requests.get(
            SOLODIT_SEARCH_URL,
            params=params,
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            results = _parse_results(data, max_results)
            _cache[cache_key] = results
            return results
        if resp.status_code in (401, 403):
            log.warning("Solodit: invalid API key")
            return []
        log.warning(f"Solodit: API returned {resp.status_code}")
    except requests.RequestException as e:
        log.debug(f"Solodit: request failed — {e}")
    except (json.JSONDecodeError, KeyError) as e:
        log.debug(f"Solodit: parse error — {e}")

    _cache[cache_key] = []
    return []


def _parse_results(data: dict, max_results: int) -> list[dict]:
    """Parse Solodit API response into structured findings."""
    results = []
    items = data.get("results", data.get("findings", data.get("data", [])))
    if isinstance(items, list):
        for item in items[:max_results]:
            finding = {
                "title": item.get("title", ""),
                "impact": item.get("impact", item.get("severity", "")),
                "description": item.get("description", item.get("body", ""))[:500],
                "mitigation": item.get("mitigation", item.get("recommendation", "")),
                "protocol": item.get("protocol", {}).get("name", "") if isinstance(item.get("protocol"), dict) else item.get("protocol", ""),
                "firm": item.get("firm", {}).get("name", "") if isinstance(item.get("firm"), dict) else item.get("firm", ""),
            }
            results.append(finding)
    return results


def get_similar_findings(
    finding_title: str,
    severity: str = "",
    max_results: int = 3,
) -> list[dict]:
    """Find similar real-world findings for a given scanner finding.

    Builds a smart search query from the finding title and detector ID.
    """
    # Build a focused search query
    # Strip common prefixes from detector IDs
    query_parts = []

    # Use the title, cleaned up
    clean_title = finding_title.replace("-", " ").replace("_", " ")
    # Remove generic words that don't help search
    skip_words = {"the", "a", "an", "in", "on", "of", "to", "is", "for", "with", "not"}
    words = [w for w in clean_title.split() if w.lower() not in skip_words]
    if words:
        query_parts.append(" ".join(words[:6]))  # Max 6 meaningful words

    # Map severity to Solodit impact format
    impact_map = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}
    impact = impact_map.get(severity.lower(), "")

    query = " ".join(query_parts)
    if not query:
        return []

    return search_findings(query, impact=impact, max_results=max_results)


def format_as_context(findings: list[dict]) -> str:
    """Format Solodit findings as context for AI prompts."""
    if not findings:
        return ""

    parts = ["## Real-World Audit Findings (from Solodit — 49K+ professional audit findings)\n"]
    for i, f in enumerate(findings, 1):
        parts.append(f"**Example {i}: {f['title']}**")
        if f.get("impact"):
            parts.append(f"- Severity: {f['impact']}")
        if f.get("protocol"):
            parts.append(f"- Protocol: {f['protocol']}")
        if f.get("firm"):
            parts.append(f"- Auditor: {f['firm']}")
        if f.get("description"):
            parts.append(f"- Description: {f['description'][:300]}")
        if f.get("mitigation"):
            parts.append(f"- Mitigation: {f['mitigation'][:200]}")
        parts.append("")

    return "\n".join(parts)


def clear_cache() -> None:
    """Clear the search cache (useful between test runs)."""
    _cache.clear()
