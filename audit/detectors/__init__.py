"""
sc4n3r — Custom Slither Detector Library
15 AST-level detectors targeting real-world exploit patterns from Solodit's 49K+ findings.

These detectors extend Slither's built-in set with checks for DeFi anti-patterns,
access control gaps, proxy safety issues, and token standard violations.

Plugin registration: Add to pyproject.toml:
    [project.entry-points."slither_analyzer.plugin"]
    sc4n3r = "audit.detectors"
"""

from .spot_price_reliance import SpotPriceReliance
from .missing_slippage import MissingSlippageCheck
from .missing_deadline import MissingDeadlineCheck
from .unprotected_initializer import UnprotectedInitializer
from .storage_collision_proxy import StorageCollisionProxy
from .single_step_ownership import SingleStepOwnership
from .unconstrained_mint import UnconstrainedMint
from .missing_zero_address import MissingZeroAddressCheck
from .read_only_reentrancy import ReadOnlyReentrancy
from .first_depositor_attack import FirstDepositorAttack
from .fee_on_transfer import FeeOnTransferTokens
from .oracle_single_source import OracleSingleSource
from .flashloan_callback import FlashloanCallbackUnprotected
from .approval_race import ApprovalRaceCondition
from .selfdestruct_implementation import SelfdestructInImplementation


def make_plugin():
    """Slither plugin entry point — returns list of detector classes."""
    return [
        SpotPriceReliance,
        MissingSlippageCheck,
        MissingDeadlineCheck,
        UnprotectedInitializer,
        StorageCollisionProxy,
        SingleStepOwnership,
        UnconstrainedMint,
        MissingZeroAddressCheck,
        ReadOnlyReentrancy,
        FirstDepositorAttack,
        FeeOnTransferTokens,
        OracleSingleSource,
        FlashloanCallbackUnprotected,
        ApprovalRaceCondition,
        SelfdestructInImplementation,
    ]
