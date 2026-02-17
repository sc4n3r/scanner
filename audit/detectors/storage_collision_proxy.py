"""
Detector: Storage Collision in Proxy
Finds potential storage slot collisions between proxy and implementation.
Solodit Tag: Proxy
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StorageCollisionProxy(AbstractDetector):
    ARGUMENT = "sc4n3r-storage-collision"
    HELP = "Potential storage collision in proxy pattern"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://sc4n3r.app/detectors/storage-collision"
    WIKI_TITLE = "Storage Collision in Proxy"
    WIKI_DESCRIPTION = (
        "Detects contracts using proxy patterns (EIP-1967, UUPS, Transparent) "
        "where implementation state variables may collide with proxy storage slots."
    )
    WIKI_RECOMMENDATION = (
        "Use EIP-1967 storage slots for proxy state. Ensure implementation contracts "
        "inherit from the same base and use storage gaps (`uint256[50] __gap`)."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A proxy contract stores its admin address at slot 0. The implementation "
        "also uses slot 0 for a different variable. An upgrade overwrites the "
        "admin, potentially locking or compromising the proxy."
    )

    PROXY_PATTERNS = {"Proxy", "ERC1967", "UUPSUpgradeable", "TransparentUpgradeableProxy"}

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            if not self._is_upgradeable(contract):
                continue
            if not self._has_storage_gap(contract) and len(contract.state_variables_declared) > 0:
                info = [
                    contract, " is upgradeable but has no storage gap (`__gap`).\n",
                    "\tAdd `uint256[50] private __gap;` to prevent storage collisions on upgrade.\n",
                ]
                res = self.generate_result(info)
                results.append(res)
        return results

    def _is_upgradeable(self, contract) -> bool:
        for parent in contract.inheritance:
            if any(p in parent.name for p in self.PROXY_PATTERNS):
                return True
            if "Upgradeable" in parent.name or "Initializable" in parent.name:
                return True
        return False

    def _has_storage_gap(self, contract) -> bool:
        for var in contract.state_variables:
            if "__gap" in var.name:
                return True
        return False
