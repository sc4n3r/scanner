"""
Detector: Fee-on-Transfer Token Handling
Finds transferFrom calls where the amount is used directly without balance diff check.
Solodit Tag: Fee On Transfer
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeOnTransferTokens(AbstractDetector):
    ARGUMENT = "sc4n3r-fee-on-transfer"
    HELP = "Token transfer amount used without accounting for transfer fees"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://sc4n3r.app/detectors/fee-on-transfer"
    WIKI_TITLE = "Fee-on-Transfer Token Handling"
    WIKI_DESCRIPTION = (
        "Detects patterns where transferFrom() amount is used directly for "
        "internal accounting without checking the actual received amount via "
        "before/after balance comparison."
    )
    WIKI_RECOMMENDATION = (
        "Use balance-before/after pattern: `uint256 before = token.balanceOf(address(this)); "
        "token.transferFrom(msg.sender, address(this), amount); "
        "uint256 received = token.balanceOf(address(this)) - before;`"
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Protocol accepts deposits of USDT (which has a transfer fee). User deposits "
        "1000 USDT but only 999 arrives. Protocol credits 1000, creating a deficit "
        "that grows with each deposit until insolvency."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_constructor or not function.is_implemented:
                    continue
                if self._has_unsafe_transfer_pattern(function):
                    info = [
                        function, " uses transfer amount directly without balance-diff check.\n",
                        "\tUse before/after balanceOf pattern for fee-on-transfer token support.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _has_unsafe_transfer_pattern(self, function) -> bool:
        has_transfer_from = False
        has_balance_check = False

        for call in function.external_calls_as_expressions:
            call_str = str(call)
            if "transferFrom" in call_str or "safeTransferFrom" in call_str:
                has_transfer_from = True
            if "balanceOf" in call_str:
                has_balance_check = True

        # Flag if transferFrom is used without a balanceOf check
        return has_transfer_from and not has_balance_check
