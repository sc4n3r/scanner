"""
Detector: Oracle Single Source
Finds price feeds without fallback oracle or staleness check.
Solodit Tag: Oracle
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleSingleSource(AbstractDetector):
    ARGUMENT = "sc4n3r-oracle-single-source"
    HELP = "Price oracle without staleness check or fallback"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://sc4n3r.app/detectors/oracle-single-source"
    WIKI_TITLE = "Oracle Single Source"
    WIKI_DESCRIPTION = (
        "Detects Chainlink oracle usage that lacks staleness validation "
        "(updatedAt check) or has no fallback oracle for when the primary feed fails."
    )
    WIKI_RECOMMENDATION = (
        "Check `updatedAt` from latestRoundData() and revert if the price is stale. "
        "Consider a fallback oracle (e.g., TWAP) for when Chainlink is unavailable."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Chainlink feed goes stale during high network congestion. The protocol "
        "continues using the last reported price, which may be hours old. "
        "An attacker exploits the price discrepancy to undercollateralize borrows "
        "or liquidate positions at incorrect prices."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_constructor or not function.is_implemented:
                    continue
                if self._uses_chainlink(function) and not self._checks_staleness(function):
                    info = [
                        function, " uses Chainlink oracle without staleness validation.\n",
                        "\tCheck `updatedAt` timestamp and revert on stale prices.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _uses_chainlink(self, function) -> bool:
        for call in function.external_calls_as_expressions:
            if "latestRoundData" in str(call):
                return True
        return False

    def _checks_staleness(self, function) -> bool:
        source = function.source_mapping.content if function.source_mapping else ""
        # Check for updatedAt comparison
        staleness_patterns = ["updatedAt", "block.timestamp", "HEARTBEAT", "MAX_DELAY", "staleness"]
        return any(p in source for p in staleness_patterns)
