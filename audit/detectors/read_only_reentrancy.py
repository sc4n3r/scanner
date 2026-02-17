"""
Detector: Read-Only Reentrancy
Finds patterns where external view calls are followed by state-dependent calculations.
Solodit Tag: Reentrancy
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReadOnlyReentrancy(AbstractDetector):
    ARGUMENT = "sc4n3r-read-only-reentrancy"
    HELP = "Potential read-only reentrancy via external view calls"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://sc4n3r.app/detectors/read-only-reentrancy"
    WIKI_TITLE = "Read-Only Reentrancy"
    WIKI_DESCRIPTION = (
        "Detects patterns where a contract reads state from an external contract "
        "via a view function during a callback, when that state may be stale or "
        "mid-update (e.g., Balancer/Curve LP token price during withdraw)."
    )
    WIKI_RECOMMENDATION = (
        "Do not rely on external view calls for pricing during callbacks. "
        "Use reentrancy guards on the data source or verify state consistency."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Contract A calls Curve pool.remove_liquidity(), which triggers a callback. "
        "During the callback, Contract B reads pool.get_virtual_price() which returns "
        "a stale value because the pool's internal state hasn't been updated yet. "
        "Contract B uses this incorrect price to issue more tokens than deserved."
    )

    PRICE_VIEW_CALLS = {
        "get_virtual_price", "getVirtualPrice", "getRate",
        "totalAssets", "convertToAssets", "convertToShares",
        "getPoolTokens", "getLatest",
    }

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_constructor or not function.is_implemented:
                    continue
                if self._has_external_view_in_callback_pattern(function):
                    info = [
                        function, " may be vulnerable to read-only reentrancy.\n",
                        "\tExternal view calls during callbacks may return stale values.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _has_external_view_in_callback_pattern(self, function) -> bool:
        # Check if function makes external calls to known price-sensitive view functions
        has_price_call = False
        has_state_write = False

        for call in function.external_calls_as_expressions:
            call_str = str(call)
            for view_fn in self.PRICE_VIEW_CALLS:
                if view_fn in call_str:
                    has_price_call = True
                    break

        if has_price_call:
            has_state_write = len(function.state_variables_written) > 0

        return has_price_call and has_state_write
