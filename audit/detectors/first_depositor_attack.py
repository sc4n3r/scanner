"""
Detector: First Depositor Attack (ERC-4626 Share Inflation)
Finds ERC-4626 vaults vulnerable to share inflation on first deposit.
Solodit Tag: Donation Attack
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FirstDepositorAttack(AbstractDetector):
    ARGUMENT = "sc4n3r-first-depositor"
    HELP = "ERC-4626 vault vulnerable to first depositor attack"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://sc4n3r.app/detectors/first-depositor-attack"
    WIKI_TITLE = "First Depositor Attack"
    WIKI_DESCRIPTION = (
        "Detects ERC-4626 vaults that don't protect against the first depositor / "
        "share inflation attack, where an attacker can manipulate share price by "
        "donating assets before the first deposit."
    )
    WIKI_RECOMMENDATION = (
        "Implement virtual shares/assets offset (e.g., OpenZeppelin's ERC4626 with "
        "_decimalsOffset), or require a minimum first deposit, or use dead shares."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "1. Attacker deposits 1 wei to get 1 share.\n"
        "2. Attacker donates 10,000 tokens directly to the vault.\n"
        "3. Victim deposits 9,999 tokens but gets 0 shares (rounded down).\n"
        "4. Attacker redeems their 1 share for ~19,999 tokens."
    )

    ERC4626_PARENTS = {"ERC4626", "ERC4626Upgradeable"}

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            if not self._is_erc4626(contract):
                continue
            if not self._has_inflation_protection(contract):
                info = [
                    contract, " is an ERC-4626 vault without first-depositor protection.\n",
                    "\tUse virtual shares offset or require minimum first deposit.\n",
                ]
                res = self.generate_result(info)
                results.append(res)
        return results

    def _is_erc4626(self, contract) -> bool:
        for parent in contract.inheritance:
            if parent.name in self.ERC4626_PARENTS:
                return True
        fn_names = {f.name for f in contract.functions}
        return "convertToShares" in fn_names and "convertToAssets" in fn_names

    def _has_inflation_protection(self, contract) -> bool:
        source = contract.source_mapping.content if contract.source_mapping else ""
        protections = [
            "_decimalsOffset", "DEAD_SHARES", "MINIMUM_SHARE",
            "virtual", "1e3", "1000", "decimalsOffset",
        ]
        for p in protections:
            if p in source:
                return True
        # Check for overridden _decimalsOffset
        for fn in contract.functions_declared:
            if fn.name == "_decimalsOffset":
                return True
        return False
