#!/usr/bin/env python3
"""
sc4n3r — Smart Contract Security Scanner
Orchestrates tool execution, aggregation, AI enhancement, and reporting.
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

import requests
import yaml

from .aggregator import aggregate_findings, filter_by_severity
from .ai_enhancer import enhance_findings
from .attack_chain import detect_attack_chains
from .centralization import analyze_centralization
from .defi_analyzer import analyze_defi
from .github_inline import post_review_comments
from .models import AuditReport, Finding
from .owasp_mapping import map_all_findings
from .parsers import parse_aderyn, parse_mythril, parse_slither, parse_solhint
from .poc_generator import generate_pocs
from .report_generator import generate_pr_comment, generate_report, generate_terminal_report
from .sarif_generator import save_sarif
from .token_compliance import analyze_tokens
from .upgrade_safety import analyze_upgrades

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
GITHUB_REF = os.getenv("GITHUB_REF", "")
GITHUB_API = "https://api.github.com"

SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "none": 0,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run_cmd(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """Execute a shell command. Returns (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        log.warning(f"{cmd[0]}: timed out ({timeout}s)")
    except FileNotFoundError:
        log.error(f"{cmd[0]}: not found")
    except Exception as e:
        log.error(f"{cmd[0]}: {e}")
    return "", "", -1


# ---------------------------------------------------------------------------
# API key validation
# ---------------------------------------------------------------------------


def validate_api_key(api_key: str, api_url: str) -> bool:
    """Validate the scanner API key against the sc4n3r dashboard.

    Returns True only if the server explicitly confirms the key is valid.
    Returns False on any error, invalid key, or network failure.
    """
    url = f"{api_url.rstrip('/')}/validate"
    try:
        resp = requests.post(
            url, headers={"Authorization": f"Bearer {api_key}"}, timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("valid"):
                log.info(f"API key valid ({data.get('email', '')})")
                return True
            log.error(f"API key rejected: {data.get('error', 'unknown')}")
            return False
        if resp.status_code in (401, 403):
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            log.error(f"API key invalid: {data.get('error', resp.status_code)}")
            return False
        log.error(f"Validation returned unexpected status {resp.status_code}")
        return False
    except requests.RequestException as e:
        log.error(f"Could not reach validation server: {e}")
        return False


# ---------------------------------------------------------------------------
# Project detection & setup
# ---------------------------------------------------------------------------


def detect_project_type() -> str:
    """Detect whether the project uses Foundry or Hardhat."""
    if Path("foundry.toml").exists():
        return "foundry"
    if Path("hardhat.config.js").exists() or Path("hardhat.config.ts").exists():
        return "hardhat"
    return "foundry"


def parse_foundry_config() -> dict:
    """Extract solidity version, source dir, and remappings from foundry.toml."""
    path = Path("foundry.toml")
    if not path.exists():
        return {}
    content = path.read_text(errors="ignore")
    cfg: dict = {}

    for pat in (
        r'solc[_-]?version\s*=\s*["\']([^"\']+)["\']',
        r'\bsolc\s*=\s*["\']([^"\']+)["\']',
    ):
        m = re.search(pat, content)
        if m:
            cfg["solidity_version"] = m.group(1).lstrip("v")
            break

    m = re.search(r'\bsrc\s*=\s*["\']([^"\']+)["\']', content)
    cfg["src"] = m.group(1) if m else "src"

    m = re.search(r'remappings\s*=\s*\[(.*?)\]', content, re.DOTALL)
    if m:
        cfg["remappings"] = re.findall(r'["\']([^"\']+)["\']', m.group(1))

    return cfg


def read_remappings_txt() -> list[str]:
    """Read remappings from remappings.txt."""
    path = Path("remappings.txt")
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#") and "=" in line
    ]


def parse_hardhat_config() -> dict:
    """Extract solidity version from hardhat.config.js/ts."""
    for name in ("hardhat.config.ts", "hardhat.config.js"):
        path = Path(name)
        if not path.exists():
            continue
        content = path.read_text(errors="ignore")
        cfg: dict = {"src": "contracts"}
        m = re.search(r'version\s*:\s*["\'](\d+\.\d+\.\d+)["\']', content)
        if m:
            cfg["solidity_version"] = m.group(1)
        return cfg
    return {}


def detect_pragma_version(contracts_path: str) -> Optional[str]:
    """Detect solidity version from pragma statements in .sol files."""
    p = Path(contracts_path)
    if not p.exists():
        return None
    for sol in sorted(p.rglob("*.sol")):
        try:
            m = re.search(
                r"pragma\s+solidity\s+[\^~>=<]*\s*(\d+\.\d+\.\d+)",
                sol.read_text(errors="ignore"),
            )
            if m:
                return m.group(1)
        except (IOError, OSError):
            continue
    return None


def setup_solc(version: str) -> None:
    """Install and activate the required solc version."""
    log.info(f"Setting up solc {version}")
    _, err, rc = run_cmd(["solc-select", "install", version], timeout=60)
    if rc != 0 and "already installed" not in (err or ""):
        log.warning(f"solc-select install: {(err or '').strip()[:200]}")
    run_cmd(["solc-select", "use", version])


def compile_project(project_type: str, config: dict) -> bool:
    """Compile the project so analysis tools have build artifacts."""
    # If user provided setup_commands, run only those — no framework-specific logic
    setup_cmds = config.get("setup_commands", [])
    if setup_cmds:
        log.info(f"Running {len(setup_cmds)} setup command(s)")
        for cmd_str in setup_cmds:
            log.info(f"  $ {cmd_str}")
            _, err, rc = run_cmd(
                ["bash", "-c", cmd_str], timeout=600,
            )
            if rc != 0:
                log.error(f"Setup command failed: {(err or '').strip()[:300]}")
                return False
        log.info("Setup completed")
        return True

    # Auto-detect flow when no setup_commands provided
    if project_type == "foundry":
        if Path(".gitmodules").exists():
            log.info("Initializing dependencies")
            run_cmd(
                ["git", "submodule", "update", "--init", "--recursive"], timeout=120,
            )
            run_cmd(["forge", "install", "--no-commit"], timeout=120)

        log.info("Compiling with forge")
        _, err, rc = run_cmd(["forge", "build"], timeout=600)
        if rc != 0:
            log.info("Build failed, retrying after forge install")
            run_cmd(["forge", "install", "--no-commit"], timeout=120)
            _, err, rc = run_cmd(["forge", "build"], timeout=600)
        if rc != 0:
            log.error(f"Compilation failed: {(err or '')[:300]}")
            return False
        log.info("Compilation succeeded")
        return True

    if project_type == "hardhat":
        if not Path("node_modules").exists():
            log.info("Installing dependencies")
            if Path("yarn.lock").exists():
                run_cmd(["yarn", "install", "--frozen-lockfile"], timeout=180)
            else:
                run_cmd(["npm", "ci"], timeout=180)
        log.info("Compiling with hardhat")
        _, err, rc = run_cmd(["npx", "hardhat", "compile"], timeout=300)
        if rc != 0:
            log.error(f"Compilation failed: {(err or '')[:300]}")
            return False
        log.info("Compilation succeeded")
        return True

    return False


def generate_remappings_json(remappings: list[str]) -> None:
    """Write remappings.json for Mythril."""
    Path("remappings.json").write_text(
        json.dumps({"remappings": remappings}, indent=2),
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_config(config_path: str) -> dict:
    """Build config: defaults -> auto-detect -> user overrides."""
    # --- Defaults ---
    default = Path(config_path)
    if not default.exists():
        default = Path(__file__).parent / "tools-config.yaml"
    config: dict = {}
    if default.exists():
        with open(default) as f:
            config = yaml.safe_load(f) or {}

    config.setdefault("contracts", {})
    config["contracts"].setdefault("path", "src/")
    config["contracts"].setdefault(
        "exclude_paths", ["lib/", "test/", "script/", "node_modules/", "mocks/"],
    )
    config.setdefault("tools", {})
    config["tools"].setdefault("slither", {"enabled": True, "timeout": 300})
    config["tools"].setdefault("aderyn", {"enabled": True, "timeout": 120})
    config["tools"].setdefault("mythril", {"enabled": False, "timeout": 600})
    config["tools"].setdefault("solhint", {"enabled": True, "timeout": 120})
    config.setdefault("severity_map", {
        "High": "high", "Medium": "medium", "Low": "low",
        "Informational": "informational", "Optimization": "informational",
        "Critical": "critical",
    })
    config.setdefault("ai", {"enabled": False})
    config.setdefault("fails_on", "high")
    config.setdefault("hide_severities", [])
    config.setdefault("report", {"output": "results/report.md"})
    config.setdefault("github", {
        "post_comment": True, "inline_comments": True, "max_comment_size": 65536,
    })

    # --- Auto-detect from project ---
    project_type = detect_project_type()
    config["project_type"] = project_type
    log.info(f"Project: {project_type}")

    if project_type == "foundry":
        fc = parse_foundry_config()
        if fc.get("solidity_version"):
            config["contracts"]["solidity_version"] = fc["solidity_version"]
        if fc.get("src"):
            config["contracts"]["path"] = fc["src"].rstrip("/") + "/"
        remappings = read_remappings_txt() or fc.get("remappings", [])
        if remappings:
            config["remappings"] = remappings

    elif project_type == "hardhat":
        hc = parse_hardhat_config()
        if hc.get("solidity_version"):
            config["contracts"]["solidity_version"] = hc["solidity_version"]
        config["contracts"]["path"] = "contracts/"

    # Fallback: detect from pragma
    if not config["contracts"].get("solidity_version"):
        v = detect_pragma_version(config["contracts"]["path"])
        if v:
            config["contracts"]["solidity_version"] = v
            log.info(f"Detected solc from pragma: {v}")

    # --- User config (overrides auto-detect) ---
    user_path = Path("sc4n3r.config.yaml")
    if user_path.exists():
        log.info("Loading sc4n3r.config.yaml")
        try:
            user = yaml.safe_load(user_path.read_text()) or {}
        except (yaml.YAMLError, IOError) as e:
            log.warning(f"Bad user config: {e}")
            user = {}

        if "solidity_version" in user:
            config["contracts"]["solidity_version"] = user["solidity_version"]
        if "remappings" in user:
            config["remappings"] = user["remappings"]
        if "exclude_paths" in user:
            config["contracts"]["exclude_paths"] = user["exclude_paths"]
        if "hide_severities" in user:
            config["hide_severities"] = user["hide_severities"]
        if "fails_on" in user:
            config["fails_on"] = user["fails_on"]
        if "mythril" in user:
            mc = user["mythril"]
            if "enabled" in mc:
                config["tools"]["mythril"]["enabled"] = mc["enabled"]
            if mc.get("targets"):
                config["mythril_targets"] = mc["targets"]
        if "ai" in user:
            ac = user["ai"]
            if "enabled" in ac:
                config["ai"]["enabled"] = ac["enabled"]
            if "analyze_severities" in ac:
                config["ai"]["analyze_only"] = ac["analyze_severities"]
            if "max_findings" in ac:
                config["ai"]["max_findings"] = ac["max_findings"]
            if "protocol_description" in ac:
                config["ai"]["protocol_description"] = ac["protocol_description"]
            if "provider" in ac:
                config["ai"]["provider"] = ac["provider"]
        if "analyzers" in user:
            config.setdefault("analyzers", {})
            for analyzer_name, analyzer_cfg in user["analyzers"].items():
                config["analyzers"].setdefault(analyzer_name, {}).update(analyzer_cfg)
        if "setup_commands" in user:
            config["setup_commands"] = user["setup_commands"]

    return config


# ---------------------------------------------------------------------------
# Tool runners
# ---------------------------------------------------------------------------


def run_slither(config: dict) -> list[Finding]:
    tc = config["tools"].get("slither", {})
    if not tc.get("enabled", True):
        return []
    log.debug("Running static analysis (pass 1)")
    out, err, _ = run_cmd(
        ["slither", ".", "--json", "-"], timeout=tc.get("timeout", 300),
    )
    # Slither writes JSON to stdout; exits 1 when findings exist (not an error)
    output = out or err
    if not output:
        log.warning("Static analysis pass 1: no output")
        return []
    findings = parse_slither(
        output, config["severity_map"], config["contracts"]["exclude_paths"],
    )
    log.debug(f"Pass 1: {len(findings)} findings")
    return findings


def run_aderyn(config: dict) -> list[Finding]:
    tc = config["tools"].get("aderyn", {})
    if not tc.get("enabled", True):
        return []
    log.debug("Running static analysis (pass 2)")
    out_path = "results/aderyn.json"
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)

    exclude = config["contracts"]["exclude_paths"]
    cmd = ["aderyn", ".", "-o", out_path]
    if exclude:
        cmd.extend(["-x", ",".join(exclude)])
    run_cmd(cmd, timeout=tc.get("timeout", 120))

    if not Path(out_path).exists():
        log.warning("Static analysis pass 2: no output")
        return []
    findings = parse_aderyn(out_path, config["severity_map"], exclude)
    Path(out_path).unlink(missing_ok=True)
    log.debug(f"Pass 2: {len(findings)} findings")
    return findings


def run_mythril(config: dict) -> list[Finding]:
    tc = config["tools"].get("mythril", {})
    if not tc.get("enabled", False):
        return []
    targets = config.get("mythril_targets", [])
    if not targets:
        log.debug("Deep analysis: no targets specified")
        return []

    log.debug(f"Running deep analysis on {len(targets)} target(s)")
    all_findings: list[Finding] = []
    for target in targets:
        if not Path(target).exists():
            log.warning(f"  skip {target} (not found)")
            continue
        log.debug(f"  analyzing {target}")
        cmd = ["myth", "analyze", target, "-o", "json"]
        if Path("remappings.json").exists():
            cmd.extend(["--solc-json", "remappings.json"])
        out, err, _ = run_cmd(cmd, timeout=tc.get("timeout", 600))
        output = out or err
        if output:
            all_findings.extend(
                parse_mythril(output, config["severity_map"], target),
            )

    log.debug(f"Deep analysis: {len(all_findings)} findings")
    return all_findings


def run_solhint(config: dict) -> list[Finding]:
    tc = config["tools"].get("solhint", {})
    if not tc.get("enabled", True):
        return []
    log.debug("Running linter analysis")
    pattern = f"{config['contracts']['path']}**/*.sol"
    out, _, _ = run_cmd(
        ["solhint", pattern, "-f", "json"], timeout=tc.get("timeout", 120),
    )
    if not out:
        log.warning("Linter analysis: no output")
        return []
    findings = parse_solhint(
        out, config["severity_map"], config["contracts"]["exclude_paths"],
    )
    log.debug(f"Linter: {len(findings)} findings")
    return findings


# ---------------------------------------------------------------------------
# Failure threshold
# ---------------------------------------------------------------------------


def check_failure_threshold(report: AuditReport, fails_on: str) -> bool:
    """Return True if findings exceed the configured severity threshold."""
    if fails_on == "none":
        return False
    threshold = SEVERITY_RANK.get(fails_on.lower(), 4)
    for severity, findings in [
        ("critical", report.critical),
        ("high", report.high),
        ("medium", report.medium),
        ("low", report.low),
    ]:
        if SEVERITY_RANK[severity] >= threshold and findings:
            log.error(f"FAILED: {len(findings)} {severity} issue(s) found")
            return True
    return False


# ---------------------------------------------------------------------------
# GitHub PR comment
# ---------------------------------------------------------------------------


def post_to_github(content: str, config: dict) -> bool:
    """Post or update a PR comment with the audit report."""
    if not GITHUB_TOKEN or not GITHUB_REPOSITORY:
        return False
    if "/pull/" not in GITHUB_REF:
        log.info("Not a PR, skipping comment")
        return False

    max_size = config.get("github", {}).get("max_comment_size", 65536)
    try:
        pr_number = GITHUB_REF.split("/")[-2]
    except (IndexError, ValueError):
        return False

    url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    if len(content) > max_size:
        content = content[: max_size - 60] + "\n\n---\n*Report truncated. See full artifact.*"

    try:
        # Update existing comment if found
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            for c in resp.json():
                if "Security Audit Report" in c.get("body", ""):
                    requests.patch(
                        f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/issues/comments/{c['id']}",
                        json={"body": content},
                        headers=headers,
                        timeout=15,
                    )
                    log.info("Updated existing PR comment")
                    return True

        resp = requests.post(url, json={"body": content}, headers=headers, timeout=15)
        if resp.status_code == 201:
            log.info("Posted PR comment")
            return True
        log.warning(f"PR comment failed: {resp.status_code}")
    except requests.RequestException as e:
        log.error(f"GitHub API error: {e}")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="sc4n3r Security Scanner")
    parser.add_argument("--config", "-c", default="audit/tools-config.yaml")
    parser.add_argument("--output", "-o", help="Report output path")
    parser.add_argument("--no-ai", action="store_true")
    parser.add_argument("--no-github", action="store_true")
    parser.add_argument("--no-fail", action="store_true")
    args = parser.parse_args()

    print()
    print("  sc4n3r — Smart Contract Security Scan")
    print("  " + "─" * 40)
    print()

    # ---- Config ----
    config = load_config(args.config)
    if args.no_ai:
        config["ai"]["enabled"] = False
    if args.no_fail:
        config["fails_on"] = "none"

    # ---- Validate API key ----
    api_key = os.getenv("SC4N3R_API_KEY", "")
    api_url = os.getenv("SC4N3R_API_URL", "https://www.sc4n3r.app/api")
    if not api_key:
        print("\n  SC4N3R_API_KEY is required. Get your key at https://sc4n3r.app")
        sys.exit(1)
    if not validate_api_key(api_key, api_url):
        print("\n  API key validation failed. Check your key at https://sc4n3r.app")
        sys.exit(1)

    # ---- Setup solc ----
    solc_version = config.get("contracts", {}).get("solidity_version", "")
    if solc_version:
        setup_solc(solc_version)

    # ---- Remappings for Mythril ----
    remappings = config.get("remappings", [])
    if remappings:
        generate_remappings_json(remappings)
        log.info(f"Remappings: {len(remappings)} entries")

    # ---- Step 1: Compile ----
    print(f"  [1/5] Compiling ({config['project_type']})...")
    compile_project(config["project_type"], config)

    # ---- Step 2: Run static analysis tools ----
    print("  [2/8] Running static analysis...")
    all_findings: list[Finding] = []
    tools_run: list[str] = []

    for name, runner in [
        ("Slither", run_slither),
        ("Aderyn", run_aderyn),
        ("Mythril", run_mythril),
        ("Solhint", run_solhint),
    ]:
        findings = runner(config)
        if findings:
            all_findings.extend(findings)
            tools_run.append(name)

    # ---- Step 3: Run sc4n3r custom analyzers ----
    print("  [3/8] Running advanced analysis...")
    analyzers = config.get("analyzers", {})

    if analyzers.get("defi", {}).get("enabled", True):
        defi_findings = analyze_defi(config)
        if defi_findings:
            all_findings.extend(defi_findings)
            tools_run.append("sc4n3r-DeFi")

    if analyzers.get("centralization", {}).get("enabled", True):
        centralization_findings = analyze_centralization(config)
        if centralization_findings:
            all_findings.extend(centralization_findings)
            tools_run.append("sc4n3r-Centralization")

    if analyzers.get("upgrade_safety", {}).get("enabled", True):
        upgrade_findings = analyze_upgrades(config)
        if upgrade_findings:
            all_findings.extend(upgrade_findings)
            tools_run.append("sc4n3r-Upgrade")

    if analyzers.get("token_compliance", {}).get("enabled", True):
        token_findings = analyze_tokens(config)
        if token_findings:
            all_findings.extend(token_findings)
            tools_run.append("sc4n3r-Token")

    # ---- Step 4: Aggregate ----
    print("  [4/8] Aggregating results...")
    deduped = aggregate_findings(all_findings)

    hide = config.get("hide_severities", [])
    if hide:
        deduped = filter_by_severity(deduped, hide)
        log.info(f"After severity filter: {len(deduped)}")

    # ---- Step 5: Map to standards ----
    print("  [5/8] Mapping to OWASP / SWC standards...")
    deduped = map_all_findings(deduped)

    # ---- Step 6: AI enhancement ----
    print("  [6/8] AI analysis...")
    enhanced = enhance_findings(deduped, config)

    # ---- Step 6b: Attack chains ----
    attack_chains = detect_attack_chains(enhanced, config)

    # ---- Step 6c: Generate PoCs ----
    enhanced = generate_pocs(enhanced, config)

    # ---- Step 7: Report ----
    print("  [7/8] Generating report...")
    report = AuditReport(findings=enhanced, tools_run=tools_run)

    # Pretty summary table
    c, h, m, l, i = len(report.critical), len(report.high), len(report.medium), len(report.low), len(report.informational)
    print("  ┌──────────────────┬───────┐")
    print("  │ Severity         │ Count │")
    print("  ├──────────────────┼───────┤")
    print(f"  │ 🔴 Critical      │  {c:>3}  │")
    print(f"  │ 🟠 High          │  {h:>3}  │")
    print(f"  │ 🟡 Medium        │  {m:>3}  │")
    print(f"  │ ⚪ Low           │  {l:>3}  │")
    print(f"  │ ℹ️  Informational │  {i:>3}  │")
    print("  ├──────────────────┼───────┤")
    print(f"  │ Total            │  {report.total:>3}  │")
    print("  └──────────────────┴───────┘")

    # Print top findings
    top = report.critical + report.high + report.medium
    if top:
        print()
        print("  Key Findings:")
        print("  ─────────────")
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}
        for f in top[:10]:
            emoji = sev_emoji.get(f.severity.lower(), "")
            fp = " (false positive)" if f.is_false_positive else ""
            print(f"  {emoji} [{f.severity.upper()}] {f.title}{fp}")
            print(f"     └─ {f.file}:{f.line}")
    print()

    sys.stdout.flush()
    sys.stderr.flush()

    # Print terminal-friendly report
    terminal_report = generate_terminal_report(report, config)
    print(terminal_report)
    sys.stdout.flush()

    # Generate markdown report for file / GitHub
    full_report = generate_report(report, config, attack_chains=attack_chains)

    output_path = args.output or config.get("report", {}).get("output", "results/report.md")
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(full_report, encoding="utf-8")
    log.info(f"Report saved: {output_path}")

    # Generate SARIF for GitHub Security Tab
    print("  [8/8] Generating SARIF output...")
    sarif_path = save_sarif(report, config)
    log.info(f"SARIF saved: {sarif_path}")

    # Post to GitHub
    if not args.no_github and config.get("github", {}).get("post_comment", True):
        pr_comment = generate_pr_comment(report, config, attack_chains=attack_chains)
        post_to_github(pr_comment, config)
        if config.get("github", {}).get("inline_comments", True) and GITHUB_TOKEN:
            post_review_comments(report, GITHUB_TOKEN)

    fails_on = config.get("fails_on", "high")
    failed = check_failure_threshold(report, fails_on)

    if failed:
        print(f"  ❌ FAILED — findings exceed '{fails_on}' threshold")
    else:
        print(f"  ✅ PASSED — no findings at or above '{fails_on}'")
    print()

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
