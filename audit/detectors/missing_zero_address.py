"""
Detector: Missing Zero Address Check
Finds setter functions that accept address parameters without checking for address(0).
Solodit Tag: Input Validation
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingZeroAddressCheck(AbstractDetector):
    ARGUMENT = "sc4n3r-missing-zero-check"
    HELP = "Critical address setter missing zero-address validation"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://sc4n3r.app/detectors/missing-zero-address"
    WIKI_TITLE = "Missing Zero Address Check"
    WIKI_DESCRIPTION = (
        "Detects setter functions for critical addresses (owner, admin, oracle, "
        "treasury) that don't validate against address(0)."
    )
    WIKI_RECOMMENDATION = (
        "Add `require(newAddress != address(0), 'zero address')` to all critical "
        "address setters."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An admin accidentally sets the fee recipient to address(0), causing "
        "all protocol fees to be permanently burned."
    )

    CRITICAL_SETTERS = {"setOwner", "setAdmin", "setOracle", "setTreasury", "setFeeRecipient",
                        "setGovernance", "setController", "setVault", "setRouter", "setFactory"}

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_declared:
                if not function.is_implemented:
                    continue
                if function.name not in self.CRITICAL_SETTERS:
                    continue
                addr_params = [p for p in function.parameters if str(p.type) == "address"]
                if not addr_params:
                    continue
                if not self._checks_zero_address(function, addr_params):
                    info = [
                        function, " sets a critical address without zero-address validation.\n",
                        "\tAdd `require(newAddr != address(0))` check.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _checks_zero_address(self, function, addr_params) -> bool:
        source = function.source_mapping.content if function.source_mapping else ""
        return "address(0)" in source or "address(0x0)" in source
