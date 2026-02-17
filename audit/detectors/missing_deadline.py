"""
Detector: Missing Deadline Check
Finds DEX interactions without block.timestamp deadline protection.
Solodit Tag: Front-Running
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingDeadlineCheck(AbstractDetector):
    ARGUMENT = "sc4n3r-missing-deadline"
    HELP = "DEX interaction missing transaction deadline"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://sc4n3r.app/detectors/missing-deadline"
    WIKI_TITLE = "Missing Deadline Check"
    WIKI_DESCRIPTION = (
        "Detects swap or liquidity functions that interact with AMMs without "
        "passing a meaningful deadline parameter."
    )
    WIKI_RECOMMENDATION = (
        "Pass a user-specified deadline parameter to AMM calls and validate "
        "block.timestamp < deadline."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A validator holds a transaction in the mempool until market conditions "
        "change unfavorably for the user. Without a deadline, the stale transaction "
        "still executes at the original (now worse) terms."
    )

    ROUTER_CALLS = {
        "swapExactTokensForTokens", "swapTokensForExactTokens",
        "swapExactETHForTokens", "swapExactTokensForETH",
        "addLiquidity", "removeLiquidity",
    }

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_constructor or not function.is_implemented:
                    continue
                if self._calls_router(function) and not self._has_deadline(function):
                    info = [
                        function, " interacts with a DEX router without a deadline parameter.\n",
                        "\tAdd a deadline check to prevent stale transaction execution.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _calls_router(self, function) -> bool:
        for call in function.external_calls_as_expressions:
            call_str = str(call)
            for router_fn in self.ROUTER_CALLS:
                if router_fn in call_str:
                    return True
        return False

    def _has_deadline(self, function) -> bool:
        param_names = {p.name.lower() for p in function.parameters}
        if "deadline" in param_names:
            return True
        # Check for block.timestamp usage in require statements
        source = function.source_mapping.content if function.source_mapping else ""
        return "block.timestamp" in source and "deadline" in source.lower()
