"""
Detector: Single-Step Ownership Transfer
Finds transferOwnership() without a pending/accept two-step pattern.
Solodit Tag: Access Control
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SingleStepOwnership(AbstractDetector):
    ARGUMENT = "sc4n3r-single-step-ownership"
    HELP = "Ownership transfer without two-step pattern"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://sc4n3r.app/detectors/single-step-ownership"
    WIKI_TITLE = "Single-Step Ownership Transfer"
    WIKI_DESCRIPTION = (
        "Detects use of single-step `transferOwnership()` without a "
        "pending owner + accept pattern. A typo in the new owner address "
        "permanently locks the contract."
    )
    WIKI_RECOMMENDATION = (
        "Use OpenZeppelin's Ownable2Step which requires the new owner to "
        "explicitly accept ownership via `acceptOwnership()`."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "The admin calls transferOwnership() with a mistyped address. "
        "Ownership is immediately transferred to an inaccessible address, "
        "permanently locking all admin functions."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            if not self._inherits_ownable(contract):
                continue
            if self._has_two_step(contract):
                continue
            info = [
                contract, " uses single-step ownership transfer.\n",
                "\tUse Ownable2Step for safer ownership transfers.\n",
            ]
            res = self.generate_result(info)
            results.append(res)
        return results

    def _inherits_ownable(self, contract) -> bool:
        for parent in contract.inheritance:
            if "Ownable" in parent.name:
                return True
        return False

    def _has_two_step(self, contract) -> bool:
        for parent in contract.inheritance:
            if "Ownable2Step" in parent.name:
                return True
        fn_names = {f.name for f in contract.functions}
        return "acceptOwnership" in fn_names or "pendingOwner" in fn_names
