"""
Detector: Spot Price Reliance
Finds functions that use pool reserves or balanceOf for pricing without TWAP.
Solodit Tag: Price Manipulation
"""

from slither.core.declarations import Function
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SpotPriceReliance(AbstractDetector):
    ARGUMENT = "sc4n3r-spot-price"
    HELP = "Spot price reliance without TWAP protection"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://sc4n3r.app/detectors/spot-price-reliance"
    WIKI_TITLE = "Spot Price Reliance"
    WIKI_DESCRIPTION = (
        "Detects functions using getReserves(), balanceOf, or pool ratios "
        "for pricing without TWAP or oracle validation."
    )
    WIKI_RECOMMENDATION = (
        "Use a TWAP oracle or Chainlink price feed instead of spot pool reserves."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker uses a flash loan to manipulate pool reserves in a single "
        "block, causing the protocol to use a manipulated spot price for swaps, "
        "liquidations, or collateral valuation."
    )

    SPOT_PRICE_CALLS = {"getReserves", "reserve0", "reserve1", "getAmountOut", "getAmountsOut"}
    SAFE_PATTERNS = {"twap", "oracle", "chainlink", "getPrice", "latestRoundData", "consult"}

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_constructor or not function.is_implemented:
                    continue
                if self._uses_spot_price(function) and not self._has_oracle_protection(contract):
                    info = [
                        function, " uses spot price from pool reserves without TWAP protection.\n",
                        "\tConsider using a time-weighted average price oracle.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _uses_spot_price(self, function: Function) -> bool:
        for call in function.high_level_calls + function.library_calls:
            _, fn = call
            if fn.name in self.SPOT_PRICE_CALLS:
                return True
        for call in function.external_calls_as_expressions:
            call_str = str(call)
            for pattern in self.SPOT_PRICE_CALLS:
                if pattern in call_str:
                    return True
        return False

    def _has_oracle_protection(self, contract) -> bool:
        source = contract.source_mapping.content if contract.source_mapping else ""
        for pattern in self.SAFE_PATTERNS:
            if pattern.lower() in source.lower():
                return True
        return False
