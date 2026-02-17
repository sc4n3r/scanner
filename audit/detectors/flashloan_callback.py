"""
Detector: Flashloan Callback Unprotected
Finds flashloan callback functions missing sender/initiator validation.
Solodit Tag: Flash Loan
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FlashloanCallbackUnprotected(AbstractDetector):
    ARGUMENT = "sc4n3r-flashloan-callback"
    HELP = "Flashloan callback missing initiator validation"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://sc4n3r.app/detectors/flashloan-callback"
    WIKI_TITLE = "Flashloan Callback Unprotected"
    WIKI_DESCRIPTION = (
        "Detects flashloan callback functions (onFlashLoan, executeOperation, "
        "receiveFlashLoan) that don't validate the initiator or msg.sender, "
        "allowing anyone to trigger the callback logic."
    )
    WIKI_RECOMMENDATION = (
        "Validate that msg.sender is the expected lending pool and that the "
        "initiator parameter equals address(this) or the expected caller."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker directly calls the onFlashLoan callback with crafted "
        "parameters, bypassing the expected flash loan flow and manipulating "
        "the contract's state (e.g., approving token transfers)."
    )

    CALLBACK_NAMES = {
        "onFlashLoan", "executeOperation", "receiveFlashLoan",
        "uniswapV2Call", "uniswapV3FlashCallback", "pancakeCall",
    }

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_declared:
                if not function.is_implemented:
                    continue
                if function.name not in self.CALLBACK_NAMES:
                    continue
                if not self._validates_caller(function):
                    info = [
                        function, " is a flashloan callback without caller validation.\n",
                        "\tValidate msg.sender is the lending pool and initiator is address(this).\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _validates_caller(self, function) -> bool:
        source = function.source_mapping.content if function.source_mapping else ""
        validation_patterns = [
            "msg.sender", "initiator", "require(", "assert(",
            "onlyPool", "onlyLendingPool", "address(this)",
        ]
        # Need at least a msg.sender or initiator check
        has_sender_check = "msg.sender" in source
        has_initiator_check = "initiator" in source and ("require" in source or "assert" in source or "if" in source)
        return has_sender_check or has_initiator_check
