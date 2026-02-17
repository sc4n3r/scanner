"""
sc4n3r — Smart Contract Security Scanner
Professional-grade automated security auditing with AI-powered analysis.
"""

from .models import AuditReport, Finding
from .aggregator import aggregate_findings
from .ai_enhancer import enhance_findings
from .attack_chain import detect_attack_chains
from .centralization import analyze_centralization
from .checklist_analyzer import analyze_checklist, generate_checklist_report
from .defi_analyzer import analyze_defi
from .owasp_mapping import map_all_findings
from .poc_generator import generate_pocs
from .poc_validator import validate_pocs
from .report_generator import generate_report, generate_pr_comment
from .sarif_generator import generate_sarif, save_sarif
from .solodit_client import search_findings, get_similar_findings
from .token_compliance import analyze_tokens
from .upgrade_safety import analyze_upgrades

__version__ = "3.0.0"
__all__ = [
    "AuditReport",
    "Finding",
    "aggregate_findings",
    "analyze_centralization",
    "analyze_checklist",
    "analyze_defi",
    "analyze_tokens",
    "analyze_upgrades",
    "detect_attack_chains",
    "enhance_findings",
    "generate_checklist_report",
    "generate_pocs",
    "generate_pr_comment",
    "generate_report",
    "generate_sarif",
    "get_similar_findings",
    "map_all_findings",
    "save_sarif",
    "search_findings",
    "validate_pocs",
]
