"""
Detector: Unprotected Initializer
Finds initialize() functions callable by anyone without initializer modifier.
Solodit Tag: Initialization
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnprotectedInitializer(AbstractDetector):
    ARGUMENT = "sc4n3r-unprotected-init"
    HELP = "Initializer function missing protection"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://sc4n3r.app/detectors/unprotected-initializer"
    WIKI_TITLE = "Unprotected Initializer"
    WIKI_DESCRIPTION = (
        "Detects initialize() functions that lack the `initializer` modifier, "
        "allowing anyone to re-initialize the contract and take ownership."
    )
    WIKI_RECOMMENDATION = (
        "Use OpenZeppelin's `initializer` modifier on all initialization functions. "
        "Add `_disableInitializers()` to the constructor of implementation contracts."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker calls initialize() on an uninitialized implementation contract "
        "behind a proxy, setting themselves as the owner and draining all funds."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if not function.is_implemented:
                    continue
                if function.name not in ("initialize", "init", "initialise"):
                    continue
                if function.visibility not in ("external", "public"):
                    continue
                modifier_names = {m.name for m in function.modifiers}
                if "initializer" not in modifier_names and "onlyInitializing" not in modifier_names:
                    info = [
                        function, " is an initializer without the `initializer` modifier.\n",
                        "\tAnyone can call this function to re-initialize the contract.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results
