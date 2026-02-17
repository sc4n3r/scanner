"""
Detector: Approval Race Condition
Finds approve() usage without increaseAllowance/decreaseAllowance pattern.
Solodit Tag: ERC-20
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ApprovalRaceCondition(AbstractDetector):
    ARGUMENT = "sc4n3r-approval-race"
    HELP = "ERC-20 approve() used without increaseAllowance pattern"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://sc4n3r.app/detectors/approval-race"
    WIKI_TITLE = "Approval Race Condition"
    WIKI_DESCRIPTION = (
        "Detects direct use of ERC-20 `approve()` to change a non-zero allowance, "
        "which is vulnerable to a front-running race condition."
    )
    WIKI_RECOMMENDATION = (
        "Use `increaseAllowance()` / `decreaseAllowance()` instead of `approve()`, "
        "or set allowance to 0 first before setting the new value."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Alice approves Bob for 100 tokens. She wants to change it to 50. "
        "Bob front-runs the second approve(), spending the original 100, "
        "then spends the new 50 — totaling 150 instead of the intended 50."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            # Only flag contracts that implement custom approve logic
            # (not just inheriting standard ERC-20)
            for function in contract.functions_declared:
                if not function.is_implemented:
                    continue
                if function.name != "approve":
                    continue
                if function.visibility not in ("external", "public"):
                    continue
                # Check if the approve sets allowance without checking current value
                if not self._checks_current_allowance(function):
                    info = [
                        function, " implements approve() without checking current allowance.\n",
                        "\tConsider requiring allowance to be 0 before setting a new value.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _checks_current_allowance(self, function) -> bool:
        source = function.source_mapping.content if function.source_mapping else ""
        # Check for patterns that mitigate the race condition
        return "allowance" in source and ("== 0" in source or "require" in source)
