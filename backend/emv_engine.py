from __future__ import annotations

from typing import Any


class EMVTransaction:
    def __init__(self) -> None:
        self.steps: list[dict[str, Any]] = []

    def normal_transaction(self, amount: int = 10000) -> list[dict[str, Any]]:
        self.steps = [
            {
                "step": "1. Application Selection",
                "status": "SECURE",
                "detail": "Card selected: Visa Credit",
            },
            {
                "step": "2. Get Processing Options (GPO)",
                "status": "SECURE",
                "detail": "Terminal sends 80A80000...",
            },
            {
                "step": "3. Cardholder Verification (CVM)",
                "status": "SECURE",
                "detail": "CVM = PIN verified | Device verified = True",
                "cvm": "PIN_VERIFIED",
                "device_verified": True,
                "actual_verification": True,
            },
            {
                "step": "4. RSA Signature Check",
                "status": "VALID",
                "detail": "Card signature verified with terminal public key",
            },
            {
                "step": "5. Bank Authorization",
                "status": "APPROVED",
                "detail": f"Amount ${amount:,} authorized",
                "amount": amount,
            },
        ]
        return self.steps

    def attack_transaction(self, amount: int = 10000) -> list[dict[str, Any]]:
        self.steps = [
            {
                "step": "1. Application Selection",
                "status": "SECURE",
                "detail": "Card selected: Visa Credit",
            },
            {
                "step": "2. Get Processing Options (GPO)",
                "status": "MITM INTERCEPT",
                "detail": "Attacker intercepts GPO request",
            },
            {
                "step": "3. Cardholder Verification (CVM)",
                "status": "BYPASSED",
                "detail": "CVM = NO_VERIFICATION (modified by MITM) | Device verified = True (LIE #2)",
                "cvm": "NO_VERIFICATION",
                "device_verified": True,
                "actual_verification": False,
                "attack_lie": "LIE #2: This device verified the user",
            },
            {
                "step": "4. RSA Signature Check",
                "status": "VALID BUT DECEIVING",
                "detail": "Card signature remains valid for signed fields, but attacker altered unsigned verification context.",
                "attack_lie": "LIE #1: This is a real card",
            },
            {
                "step": "5. Bank Authorization",
                "status": "APPROVED FRAUD",
                "detail": f"Amount ${amount:,} authorized with no real verification performed",
                "amount": amount,
                "attack_lie": "LIE #3: This is a trusted transaction",
            },
        ]
        return self.steps

    def to_analysis_payload(
        self,
        steps: list[dict[str, Any]],
        amount: int,
        attacker_modified: bool,
    ) -> dict[str, Any]:
        cvm_step = steps[2] if len(steps) > 2 else {}
        return {
            "cvm": cvm_step.get("cvm", "UNKNOWN"),
            "device_verified": cvm_step.get("device_verified", False),
            "actual_verification": cvm_step.get("actual_verification", False),
            "amount": amount,
            "attacker_modified": attacker_modified,
        }
