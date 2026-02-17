"""
Detector: Selfdestruct in Implementation
Finds selfdestruct/delegatecall in UUPS/proxy implementation contracts.
Solodit Tag: Proxy
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SelfdestructInImplementation(AbstractDetector):
    ARGUMENT = "sc4n3r-selfdestruct-impl"
    HELP = "selfdestruct in proxy implementation contract"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://sc4n3r.app/detectors/selfdestruct-implementation"
    WIKI_TITLE = "Selfdestruct in Implementation"
    WIKI_DESCRIPTION = (
        "Detects usage of `selfdestruct` (or `delegatecall` to untrusted targets) "
        "in contracts that serve as UUPS or proxy implementations."
    )
    WIKI_RECOMMENDATION = (
        "Never use selfdestruct in implementation contracts. Remove any "
        "delegatecall to user-controlled addresses."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker calls selfdestruct on the implementation contract directly "
        "(not through the proxy). This destroys the implementation's bytecode, "
        "bricking the proxy and freezing all funds."
    )

    IMPL_PATTERNS = {"UUPSUpgradeable", "Initializable", "ERC1967Upgrade"}

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            if not self._is_implementation(contract):
                continue
            for function in contract.functions:
                if not function.is_implemented:
                    continue
                source = function.source_mapping.content if function.source_mapping else ""
                if "selfdestruct" in source or "suicide" in source:
                    info = [
                        function, " contains selfdestruct in a proxy implementation.\n",
                        "\tThis can brick the proxy. Remove selfdestruct from implementations.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _is_implementation(self, contract) -> bool:
        for parent in contract.inheritance:
            if parent.name in self.IMPL_PATTERNS:
                return True
        return False
