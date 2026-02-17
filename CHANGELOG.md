# Changelog

All notable changes to sc4n3r will be documented in this file.

## [3.0.0] - 2026-02-17

### Added — $40/mo Pro Features
- **Solodit-powered AI analysis** — 49K+ real audit findings as context for smarter false positive filtering and attack scenario generation
- **Audit checklist engine** — 380+ systematic security checks from Cyfrin's audit checklist, mirroring professional audit methodology
- **Validated PoCs** — AI-generated Foundry PoCs are now compiled (`forge build`) and executed (`forge test`) with iterative AI repair (max 3 retries)
- **15 custom Slither detectors** — AST-level detection targeting real-world exploit patterns: spot price reliance, missing slippage/deadline, unprotected initializers, storage collisions, single-step ownership, unconstrained mint, zero-address checks, read-only reentrancy, first depositor attack, fee-on-transfer, oracle staleness, flashloan callback, approval race, selfdestruct in implementation
- **Confidence scoring** — findings scored 0.0-1.0 based on evidence level (static=0.7, AI-confirmed=0.9, PoC-validated=1.0)
- **Solodit API client** — queries real-world findings as few-shot examples for AI analysis and PoC generation

### Improved
- **AI accuracy** — Solodit real-world findings as context dramatically improve false positive filtering
- **PoC quality** — validated PoCs with compilation + execution verification, iterative repair loop
- **Pipeline** — expanded from 8 to 10 steps: added checklist analysis and PoC validation
- **Report** — checklist coverage section, confidence scores, PoC validation status (Verified/Compiles/Generated)

## [2.0.0] - 2026-02-17

### Added — Professional-Grade Analysis
- **DeFi-specific vulnerability detection** — flash loan susceptibility, oracle manipulation risk, MEV exposure, missing slippage/deadline protection
- **Centralization risk analysis** — single-owner patterns, missing timelock, unconstrained minting, no multisig detection
- **Proxy & upgrade safety checks** — storage collisions, uninitialized implementations, missing _disableInitializers, UUPS validation
- **Token standard compliance** — ERC-20/721/1155/4626 compliance verification, inflation attack detection, approval race conditions
- **AI-generated Proof of Concepts** — executable Foundry test PoCs for critical/high findings
- **Cross-finding attack chain detection** — AI identifies how multiple findings combine into critical attack paths
- **OWASP Smart Contract Top 10 mapping** — all findings mapped to OWASP SC Top 10 (2025) with coverage matrix
- **SWC Registry mapping** — findings linked to Smart Contract Weakness Classification IDs
- **SARIF v2.1.0 output** — findings appear in GitHub's native Security Tab alongside CodeQL
- **Executive summary with risk grade** (A-F) — one-paragraph overview for non-technical stakeholders
- **Remediation priority matrix** — findings grouped into Fix Now / Fix Before Deploy / Consider Fixing / Accepted Risk
- **Protocol context-aware AI** — describe your protocol in config for business-logic-aware analysis

### Improved
- **AI prompts** — chain-of-thought reasoning with few-shot examples for higher accuracy
- **Report quality** — professional audit-grade reports with OWASP coverage, priority matrix, and attack chains
- **Pipeline steps** — expanded from 5 to 8 steps for comprehensive analysis
- **Configuration** — new `analyzers` section to enable/disable custom analysis modules

## [1.0.0] - 2026-02-15

### Added
- Multi-engine static analysis with deduplication
- AI-powered false positive filtering (Gemini and Claude support)
- GitHub PR comments with full audit summary
- Inline review comments on affected lines
- Markdown report saved as build artifact
- Auto-detection of Foundry and Hardhat projects
- Auto-detection of Solidity compiler version and remappings
- Configurable severity thresholds for CI pipeline failure
- Optional deep analysis for critical contracts
- Custom `setup_commands` for project-specific build steps
- Privacy-first: code never leaves the GitHub Actions runner
