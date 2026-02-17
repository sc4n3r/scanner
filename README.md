# sc4n3r

The closest thing to a professional smart contract audit in your CI/CD pipeline.

sc4n3r combines multi-engine static analysis, AI-powered false positive filtering, DeFi-specific vulnerability detection, automated proof-of-concept generation, and professional-grade reporting — all running as a GitHub Action.

---

## What Makes sc4n3r Different

| Feature | Free Tools | Other Scanners | sc4n3r | Professional Audit |
|---------|-----------|----------------|--------|-------------------|
| Static analysis (Slither, Aderyn) | ✅ | ✅ | ✅ | ✅ |
| Multi-tool aggregation | — | — | ✅ | — |
| AI false-positive filtering | — | Some | ✅ | ✅ |
| DeFi-specific detection | — | — | ✅ | ✅ |
| Centralization risk analysis | — | — | ✅ | ✅ |
| Upgrade safety checks | — | Some | ✅ | ✅ |
| Token standard compliance | — | — | ✅ | ✅ |
| AI-generated PoCs | — | — | ✅ | ✅ |
| Attack chain detection | — | — | ✅ | ✅ |
| OWASP SC Top 10 mapping | — | — | ✅ | ✅ |
| SARIF / GitHub Security Tab | — | Some | ✅ | — |
| Executive risk grading | — | — | ✅ | ✅ |
| Inline PR annotations | — | — | ✅ | — |

---

## Quick Start

### Step 1: Add the workflow

Create `.github/workflows/sc4n3r.yml` in your Solidity project:

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write
  security-events: write     # Required for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: sc4n3r
        uses: sc4n3r/scanner@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          api_key: ${{ secrets.SC4N3R_API_KEY }}

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/sc4n3r.sarif
          category: sc4n3r

      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: results/
```

That's it. The scanner auto-detects your project type (Foundry or Hardhat), compiler version, and remappings.

### Step 2 (optional): Customize

Create `sc4n3r.config.yaml` in your project root:

```yaml
# All fields are optional — the scanner auto-detects everything

# Commands to run before scanning
# setup_commands:
#   - "forge install"
#   - "forge build"

# Paths to exclude
exclude_paths:
  - "test/"
  - "script/"
  - "lib/"
  - "node_modules/"

# Fail CI on this severity or above
fails_on: "high"

# Deep analysis (slower but more thorough)
mythril:
  enabled: false
  targets: []

# sc4n3r custom analyzers (all enabled by default)
# analyzers:
#   defi:
#     enabled: true         # Flash loan, oracle, MEV detection
#   centralization:
#     enabled: true         # Admin key, timelock, multisig checks
#   upgrade_safety:
#     enabled: true         # Proxy, storage collision, initializer checks
#   token_compliance:
#     enabled: true         # ERC-20/721/1155/4626 compliance

# AI enhancement
ai:
  enabled: true
  # provider: "gemini"     # or "claude"
  analyze_severities: ["critical", "high", "medium"]
  max_findings: 25
  # Describe your protocol for context-aware analysis:
  # protocol_description: "A lending protocol that allows deposit/borrow"
```

---

## What You Get

On every pull request, sc4n3r delivers:

### 1. PR Comment with Full Audit Report
- **Risk Grade** (A-F) based on weighted severity analysis
- Severity breakdown table
- Attack chains detected across multiple findings
- Detailed findings with attack scenarios, impact, and fixes

### 2. Inline Review Comments
- Annotations on the exact lines with issues
- Severity, description, and fix suggestion per comment

### 3. GitHub Security Tab (SARIF)
- Findings appear in GitHub's native Security tab
- Track, dismiss, and manage findings alongside CodeQL

### 4. Full Markdown Report (Artifact)
- Executive summary with risk assessment
- OWASP Smart Contract Top 10 coverage matrix
- Remediation priority matrix (Fix Now / Fix Before Deploy / Consider Fixing)
- Detailed findings with code snippets and PoCs
- Attack chain analysis

### 5. Proof of Concepts (PoCs)
- AI-generated Foundry test exploits for critical/high findings
- Saved to `results/pocs/` as executable `.t.sol` files

---

## Analysis Engines

### External Static Analysis
| Tool | What It Detects |
|------|----------------|
| **Slither** | Reentrancy, unchecked calls, state variable issues, 80+ detectors |
| **Aderyn** | Security patterns, gas optimizations, best practice violations |
| **Mythril** | Symbolic execution for deep path analysis (optional) |
| **Solhint** | Solidity linting and style violations |

### sc4n3r Custom Analyzers
| Analyzer | What It Detects |
|----------|----------------|
| **DeFi** | Flash loan susceptibility, oracle manipulation, MEV exposure, missing slippage/deadline |
| **Centralization** | Single-owner risks, missing timelock, unconstrained minting, no multisig |
| **Upgrade Safety** | Proxy patterns, storage collisions, uninitialized implementations, missing _disableInitializers |
| **Token Compliance** | ERC-20/721/1155/4626 violations, inflation attacks, approval race conditions |

### AI Enhancement
| Capability | Description |
|-----------|-------------|
| **False positive filtering** | Chain-of-thought analysis with few-shot examples |
| **Attack scenarios** | Step-by-step exploitation paths |
| **Impact assessment** | Financial and protocol impact analysis |
| **Fix suggestions** | Diff-style code fixes |
| **PoC generation** | Executable Foundry test exploits |
| **Attack chain detection** | Cross-finding correlation for combined attack paths |

---

## Severity Classification

sc4n3r maps all findings to industry standards:

### OWASP Smart Contract Top 10 (2025)
| # | Category |
|---|----------|
| SC01 | Access Control Vulnerabilities |
| SC02 | Business Logic Vulnerabilities |
| SC03 | Price Oracle Manipulation |
| SC04 | Flash Loan-Facilitated Attacks |
| SC05 | Lack of Input Validation |
| SC06 | Unchecked External Calls |
| SC07 | Arithmetic Errors |
| SC08 | Reentrancy Attacks |
| SC09 | Integer Overflow and Underflow |
| SC10 | Proxy & Upgradeability Vulnerabilities |

### Risk Grades
| Grade | Meaning |
|-------|---------|
| A | Excellent — no significant issues |
| B | Good — minor issues only |
| C | Moderate — some issues need attention |
| D | Concerning — significant issues found |
| F | Critical — severe vulnerabilities, do not deploy |

### Pipeline Failure Thresholds
| `fails_on` | Pipeline fails when |
|------------|---------------------|
| `critical` | Critical findings exist |
| `high` | Critical or High findings exist |
| `medium` | Critical, High, or Medium findings exist |
| `low` | Any finding except Informational |
| `none` | Never fails |

---

## Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `token` | Yes | — | `GITHUB_TOKEN` for PR comments |
| `api_key` | Yes | — | sc4n3r API key (from [dashboard](https://sc4n3r.app)) |
| `api_url` | No | `https://www.sc4n3r.app/api` | API endpoint |
| `fail_on` | No | `high` | Override `fails_on` from config |
| `no_ai` | No | `false` | Disable AI enhancement |

## Action Outputs

| Output | Description |
|--------|-------------|
| `report_path` | Path to `results/report.md` |
| `sarif_path` | Path to `results/sc4n3r.sarif` |
| `critical_count` | Number of critical findings |
| `high_count` | Number of high severity findings |
| `medium_count` | Number of medium severity findings |
| `total_count` | Total number of findings |

---

## AI Providers

| Provider | Config | Environment Variable |
|----------|--------|---------------------|
| Gemini | `provider: "gemini"` | `GEMINI_API_KEY` |
| Claude | `provider: "claude"` | `ANTHROPIC_API_KEY` |

---

## Privacy

- Your code **never leaves your GitHub Actions runner**
- Only API key validation hits sc4n3r servers
- All analysis runs locally inside the Docker container
- Findings stay in your PR comments and artifacts

---

## How It Works

```
 1. Detect     → Identifies Foundry/Hardhat, reads compiler version and remappings
 2. Compile    → Builds the project (forge build / hardhat compile)
 3. Scan       → Runs Slither, Aderyn, Mythril, Solhint
 4. Analyze    → Runs DeFi, centralization, upgrade, and token analyzers
 5. Aggregate  → Deduplicates findings across all engines
 6. Map        → Maps findings to OWASP SC Top 10 and SWC standards
 7. AI         → Filters false positives, generates attack scenarios, PoCs, and attack chains
 8. Report     → Outputs SARIF, markdown report, PR comment, and inline annotations
```

---

## Local Development

### Build

```bash
docker build -t sc4n3r .
```

### Run

```bash
docker run --rm \
  -v /path/to/your/solidity-project:/target \
  -e SC4N3R_API_KEY=your-key \
  -e GEMINI_API_KEY=your-key \
  sc4n3r --no-github
```

| Flag | Description |
|------|-------------|
| `--no-github` | Skip PR comments (for local runs) |
| `--no-ai` | Skip AI analysis |
| `--no-fail` | Don't exit with error on findings |

---

## Project Structure

```
scanner/
├── action.yaml              # GitHub Action definition
├── Dockerfile               # Scanner image
├── entrypoint.py            # Container entrypoint
├── sc4n3r.config.yaml       # Example config
├── audit/
│   ├── run_audit.py         # Main orchestrator
│   ├── models.py            # Data models (Finding, AuditReport)
│   ├── aggregator.py        # Deduplication and filtering
│   ├── ai_enhancer.py       # AI analysis (Gemini / Claude)
│   ├── attack_chain.py      # Cross-finding attack chain detection
│   ├── centralization.py    # Centralization risk detection
│   ├── defi_analyzer.py     # DeFi-specific vulnerability detection
│   ├── github_inline.py     # PR inline comments
│   ├── owasp_mapping.py     # OWASP SC Top 10 + SWC mapping
│   ├── poc_generator.py     # AI-powered PoC generation
│   ├── report_generator.py  # Report builder (executive summary, priority matrix)
│   ├── sarif_generator.py   # SARIF v2.1.0 output for GitHub Security Tab
│   ├── token_compliance.py  # ERC-20/721/1155/4626 compliance checks
│   ├── upgrade_safety.py    # Proxy & upgrade safety checks
│   ├── tools-config.yaml    # Default config
│   └── parsers/             # Tool output parsers
└── .github/workflows/
    ├── build.yml            # Docker image CI/CD
    └── scan.yml             # Reusable scan workflow
```

---

## License

[Business Source License 1.1](LICENSE) — Free to use in your projects. See LICENSE for details.
