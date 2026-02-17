"""
Detector: Unconstrained Mint
Finds mint() functions callable by owner with no supply cap or timelock.
Solodit Tag: Rug Pull
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnconstrainedMint(AbstractDetector):
    ARGUMENT = "sc4n3r-unconstrained-mint"
    HELP = "Mint function without supply cap or timelock"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://sc4n3r.app/detectors/unconstrained-mint"
    WIKI_TITLE = "Unconstrained Mint"
    WIKI_DESCRIPTION = (
        "Detects mint functions that can be called by a privileged role without "
        "a maximum supply cap, rate limit, or timelock constraint."
    )
    WIKI_RECOMMENDATION = (
        "Add a MAX_SUPPLY cap check, or use a timelock on minting operations."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A compromised owner key calls mint() to create unlimited tokens, "
        "dumps them on the market, and drains all liquidity."
    )

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_declared:
                if not function.is_implemented:
                    continue
                if function.name not in ("mint", "_mint", "mintTo", "mintTokens"):
                    continue
                if function.visibility not in ("external", "public"):
                    continue
                if not self._has_supply_cap(function, contract):
                    info = [
                        function, " allows minting without a supply cap.\n",
                        "\tAdd a MAX_SUPPLY check to prevent unlimited token inflation.\n",
                    ]
                    res = self.generate_result(info)
                    results.append(res)
        return results

    def _has_supply_cap(self, function, contract) -> bool:
        source = function.source_mapping.content if function.source_mapping else ""
        cap_patterns = ["MAX_SUPPLY", "maxSupply", "cap", "MAX_TOTAL", "maxMint"]
        for pattern in cap_patterns:
            if pattern in source:
                return True
        # Check if contract has a cap variable
        for var in contract.state_variables:
            if any(p.lower() in var.name.lower() for p in cap_patterns):
                return True
        return False
