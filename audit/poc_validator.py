"""
sc4n3r — PoC Validation Pipeline
Compiles and executes AI-generated Foundry PoCs to verify exploitability.
Uses iterative AI repair when compilation or execution fails.
"""

import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .models import Finding

log = logging.getLogger(__name__)

MAX_RETRIES = 3
COMPILE_TIMEOUT = 120
TEST_TIMEOUT = 180


def _run_cmd(cmd: list[str], timeout: int = 120, cwd: str = ".") -> tuple[str, str, int]:
    """Execute a command and return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        log.warning(f"PoC validation: {cmd[0]} timed out ({timeout}s)")
    except FileNotFoundError:
        log.warning(f"PoC validation: {cmd[0]} not found")
    except Exception as e:
        log.warning(f"PoC validation: {e}")
    return "", "", -1


def _query_ai_for_fix(
    poc_code: str,
    error_msg: str,
    finding: Finding,
    api_key: str,
    provider: str,
    model: str,
    timeout: int,
) -> Optional[str]:
    """Ask AI to fix a failing PoC based on error messages."""
    import requests

    prompt = f"""You are an expert Foundry test developer. A Proof of Concept test failed to compile/run. Fix the code.

## Original Vulnerability
- **Title:** {finding.title}
- **File:** {finding.file}
- **Line:** {finding.line}

## Current PoC Code (FAILING)
```solidity
{poc_code}
```

## Error
```
{error_msg[:2000]}
```

## Instructions
Fix the Solidity test code so it compiles and runs successfully with `forge test`.
Common fixes:
- Fix import paths (use relative paths from project root)
- Fix pragma version to match the project
- Fix interface mismatches (wrong function signatures)
- Add missing setup steps (deploy dependencies, fund accounts)
- Fix assertion logic

Generate ONLY the complete fixed Solidity test file. No explanations."""

    if provider == "claude":
        from .poc_generator import CLAUDE_URL
        try:
            resp = requests.post(
                CLAUDE_URL,
                json={"model": model, "max_tokens": 4096, "messages": [{"role": "user", "content": prompt}]},
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                text = resp.json()["content"][0]["text"]
                return _extract_code(text)
        except Exception as e:
            log.debug(f"PoC fix AI error: {e}")
        return None

    from .poc_generator import GEMINI_URL
    url = f"{GEMINI_URL.format(model=model)}?key={api_key}"
    try:
        resp = requests.post(
            url,
            json={"contents": [{"parts": [{"text": prompt}]}]},
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            return _extract_code(text)
    except Exception as e:
        log.debug(f"PoC fix AI error: {e}")
    return None


def _extract_code(response: str) -> str:
    """Extract Solidity code from AI response."""
    m = re.search(r"```(?:solidity)?\s*\n(.*?)```", response, re.DOTALL)
    if m:
        return m.group(1).strip()
    if "function" in response and "pragma" in response:
        return response.strip()
    return ""


def validate_poc(
    finding: Finding,
    config: dict,
) -> tuple[bool, bool]:
    """Validate a PoC by compiling and executing it.

    Returns:
        (compiles: bool, passes: bool)
    """
    if not finding.poc_code:
        return False, False

    ai = config.get("ai", {})
    provider = ai.get("provider", "gemini").lower()
    from .ai_enhancer import PROVIDER_DEFAULTS
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["gemini"])
    api_key = os.environ.get(defaults["env"], "")
    model = ai.get("model", defaults["model"])
    timeout = ai.get("timeout", 90) + 30

    poc_code = finding.poc_code
    # Generate a unique test filename
    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", finding.title[:30])
    test_filename = f"Sc4n3rPoC_{safe_name}.t.sol"
    test_path = Path("test") / test_filename

    # Extract contract name from PoC for targeted test execution
    contract_match = re.search(r"contract\s+(\w+)\s+is\s+Test", poc_code)
    contract_name = contract_match.group(1) if contract_match else ""

    compiles = False
    passes = False

    for attempt in range(1, MAX_RETRIES + 1):
        log.info(f"    PoC validation attempt {attempt}/{MAX_RETRIES}")

        # Write PoC to test directory
        try:
            test_path.parent.mkdir(parents=True, exist_ok=True)
            test_path.write_text(poc_code, encoding="utf-8")
        except (IOError, OSError) as e:
            log.warning(f"    Could not write PoC file: {e}")
            break

        # Step 1: Compile
        stdout, stderr, rc = _run_cmd(
            ["forge", "build"], timeout=COMPILE_TIMEOUT,
        )

        if rc != 0:
            error_msg = stderr or stdout
            log.info(f"    Compile failed (attempt {attempt})")

            # Clean up before retry
            _cleanup(test_path)

            if attempt < MAX_RETRIES and api_key:
                fixed = _query_ai_for_fix(
                    poc_code, error_msg, finding, api_key, provider, model, timeout,
                )
                if fixed:
                    poc_code = fixed
                    continue
            break

        compiles = True
        log.info(f"    Compile succeeded")

        # Step 2: Execute test
        test_cmd = ["forge", "test", "--json", "-vvvv"]
        if contract_name:
            test_cmd.extend(["--match-contract", contract_name])

        stdout, stderr, rc = _run_cmd(test_cmd, timeout=TEST_TIMEOUT)

        if rc == 0 and stdout:
            # Parse JSON test results
            try:
                # forge test --json outputs JSON per line
                for line in stdout.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        result = json.loads(line)
                        # Check if any test passed
                        if isinstance(result, dict):
                            for suite_result in result.values():
                                if isinstance(suite_result, dict):
                                    test_results = suite_result.get("test_results", {})
                                    for test_name, test_data in test_results.items():
                                        if isinstance(test_data, dict):
                                            status = test_data.get("status", "")
                                            if status == "Success":
                                                passes = True
                                                log.info(f"    Test PASSED: {test_name}")
                    except json.JSONDecodeError:
                        continue
            except Exception as e:
                log.debug(f"    Parse test output error: {e}")

        if not passes:
            log.info(f"    Test failed or no passing tests found")
            error_msg = stderr or stdout
            _cleanup(test_path)

            if attempt < MAX_RETRIES and api_key:
                fixed = _query_ai_for_fix(
                    poc_code, error_msg[:2000], finding, api_key, provider, model, timeout,
                )
                if fixed:
                    poc_code = fixed
                    continue
            break
        else:
            break

    # Clean up test file
    _cleanup(test_path)

    # Update the finding's PoC code with the (potentially fixed) version
    if compiles:
        finding.poc_code = poc_code

    return compiles, passes


def _cleanup(test_path: Path) -> None:
    """Remove the temporary test file."""
    try:
        test_path.unlink(missing_ok=True)
    except (IOError, OSError):
        pass


def validate_pocs(findings: list[Finding], config: dict) -> list[Finding]:
    """Validate all PoCs in the findings list. Mutates findings in-place."""
    ai = config.get("ai", {})
    if not ai.get("enabled", False):
        return findings

    targets = [f for f in findings if f.poc_code and not f.is_false_positive]
    if not targets:
        log.info("PoC validation: no PoCs to validate")
        return findings

    log.info(f"PoC validation: validating {len(targets)} PoC(s)")

    for i, finding in enumerate(targets, 1):
        log.info(f"  [{i}/{len(targets)}] {finding.title[:50]}")
        compiles, passes = validate_poc(finding, config)
        finding.poc_compiles = compiles
        finding.poc_validated = passes

        status = "VERIFIED" if passes else ("compiles" if compiles else "failed")
        log.info(f"    Result: {status}")

    validated = sum(1 for f in findings if getattr(f, "poc_validated", False))
    compiled = sum(1 for f in findings if getattr(f, "poc_compiles", False))
    log.info(f"PoC validation: {compiled} compile, {validated} verified")
    return findings
