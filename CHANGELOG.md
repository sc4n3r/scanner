# Changelog

All notable changes to sc4n3r will be documented in this file.

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
