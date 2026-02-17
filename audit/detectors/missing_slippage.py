"""
Detector: Missing Slippage Check
Finds swap/deposit/withdraw functions without minAmountOut parameter.
Solodit Tag: Slippage
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingSlippageCheck(AbstractDetector):
    ARGUMENT = "sc4n3r-missing-slippage"
    HELP = "Swap or deposit function missing slippage protection"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://sc4n3r.app/detectors/missing-slippage"
    WIKI_TITLE = "Missing Slippage Check"
    WIKI_DESCRIPTION = (
        "Detects swap, deposit, or withdraw functions that lack a minimum output "
        "amount parameter (minAmountOut / minShares) for slippage protection."
    )
    WIKI_RECOMMENDATION = (
        "Add a minAmountOut parameter and require the output meets minimum expectations."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker sandwich-attacks a user's swap transaction. Without slippage "
        "protection, the user receives far fewer tokens than expected."
    )

    SWAP_KEYWORDS = {"swap", "exchange", "deposit", "withdraw", "redeem", "removeLiquidity"}
    SLIPPAGE_PARAMS = {"minAmountOut", "minAmount", "amountOutMin", "minShares", "minTokens", "deadline", "slippage"}

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_constructor or not function.is_implemented:
                    continue
                if not function.visibility in ("external", "public"):
                    continue
                if self._is_swap_function(function) and not self._has_slippage_param(function):
                    info = [
                        function, " performs a swap/deposit/withdraw without slippage protection.\n",
                        "\tAdd a minAmountOut parameter to protect users from sandwich attacks.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _is_swap_function(self, function) -> bool:
        name_lower = function.name.lower()
        return any(kw in name_lower for kw in self.SWAP_KEYWORDS)

    def _has_slippage_param(self, function) -> bool:
        param_names = {p.name.lower() for p in function.parameters}
        return any(sp.lower() in param_names for sp in self.SLIPPAGE_PARAMS)
