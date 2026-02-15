# sc4n3r

Automated smart contract security scanner. Analyzes your Solidity code for vulnerabilities, filters false positives with AI, and posts actionable findings directly to your pull requests.

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

      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: results/report.md
```

That's it. The scanner auto-detects your project type (Foundry or Hardhat), compiler version, and remappings.

### Step 2 (optional): Customize

Create `sc4n3r.config.yaml` in your project root:

```yaml
# All fields are optional

# Commands to run before scanning (install deps, compile, etc.)
# setup_commands:
#   - "forge install"
#   - "forge build"

# Paths to exclude
exclude_paths:
  - "test/"
  - "script/"
  - "lib/"
  - "node_modules/"

# Fail CI on this severity or above (critical/high/medium/low/none)
fails_on: "high"

# Deep analysis (disabled by default)
mythril:
  enabled: false
  targets: []

# AI enhancement
ai:
  enabled: true
  provider: "gemini"  # or "claude"
  analyze_severities:
    - "critical"
    - "high"
    - "medium"
  max_findings: 25
```

### Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `token` | Yes | — | `GITHUB_TOKEN` for PR comments |
| `api_key` | No | — | sc4n3r API key (from [dashboard](https://sc4n3r.app)) |
| `api_url` | No | `https://sc4n3r.app/api` | API endpoint |
| `fail_on` | No | `high` | Override `fails_on` from config |
| `no_ai` | No | `false` | Disable AI enhancement |

### Pipeline Failure Thresholds

| `fails_on` | Pipeline fails when |
|------------|---------------------|
| `critical` | Critical findings exist |
| `high` | Critical or High findings exist |
| `medium` | Critical, High, or Medium findings exist |
| `low` | Any finding except Informational |
| `none` | Never fails |

### What You Get

On every pull request:

1. **PR comment** with full audit summary, severity breakdown, and detailed findings
2. **Inline review comments** on the exact lines with issues
3. **Markdown report** saved as a build artifact (`results/report.md`)

Each finding includes:
- Title and severity
- File location with proof of code
- Attack scenario (AI-generated)
- Recommended fix with diff (AI-generated)

### AI Providers

sc4n3r supports two AI providers for finding analysis:

| Provider | Config | Environment Variable |
|----------|--------|---------------------|
| Gemini | `provider: "gemini"` | `GEMINI_API_KEY` |
| Claude | `provider: "claude"` | `ANTHROPIC_API_KEY` |

### Privacy

- Your code **never leaves your GitHub Actions runner**
- Only API key validation hits sc4n3r servers (if you use an API key)
- Findings stay in your PR comments and artifacts

---

## Local Development

For contributors working on the scanner itself.

### Prerequisites

- Docker
- A Solidity project to test against

### Build

```bash
docker build -t sc4n3r .
```

### Run

```bash
docker run --rm \
  -v /path/to/your/solidity-project:/target \
  -e GEMINI_API_KEY=your-key \
  sc4n3r --no-github
```

Flags:

| Flag | Description |
|------|-------------|
| `--no-github` | Skip PR comments (for local runs) |
| `--no-ai` | Skip AI analysis |
| `--no-fail` | Don't exit with error on findings |

### Project Structure

```
scanner/
├── action.yaml              # GitHub Action definition
├── Dockerfile               # Scanner image
├── entrypoint.py            # Container entrypoint
├── sc4n3r.config.yaml       # Example config
├── audit/
│   ├── run_audit.py         # Main orchestrator
│   ├── models.py            # Data models
│   ├── aggregator.py        # Deduplication and filtering
│   ├── ai_enhancer.py       # AI analysis (Gemini / Claude)
│   ├── report_generator.py  # Report builder
│   ├── github_inline.py     # PR inline comments
│   ├── tools-config.yaml    # Default config
│   └── parsers/             # Tool output parsers
└── .github/workflows/
    ├── build.yml            # Docker image CI/CD
    └── scan.yml             # Reusable scan workflow
```

### How It Works

1. **Detect** — Identifies Foundry or Hardhat, reads compiler version and remappings
2. **Setup** — Runs `setup_commands` if configured, or auto-installs dependencies
3. **Compile** — Builds the project
4. **Scan** — Runs multiple static analysis engines
5. **Deduplicate** — Merges findings by `file:line:detector`
6. **AI Analysis** — Filters false positives, generates attack scenarios and fixes
7. **Report** — Outputs report, posts PR comment, adds inline annotations

---

## License

[Business Source License 1.1](LICENSE) — Free to use in your projects. See LICENSE for details.
