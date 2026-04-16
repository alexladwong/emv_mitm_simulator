from __future__ import annotations

from typing import Any, Callable


class RiskEngine:
    def __init__(self) -> None:
        self.risk_rules: list[dict[str, Any]] = [
            {
                "name": "Suspicious CVM",
                "condition": lambda t: t.get("cvm") == "NO_VERIFICATION",
                "risk_score": 95,
                "message": "CRITICAL: No cardholder verification performed",
            },
            {
                "name": "Device Trust Mismatch",
                "condition": lambda t: t.get("device_verified") is True and t.get("actual_verification") is False,
                "risk_score": 100,
                "message": "LIE DETECTED: Device claims verification but none occurred",
            },
            {
                "name": "Unusual Transaction Amount",
                "condition": lambda t: t.get("amount", 0) > 5000,
                "risk_score": 60,
                "message": "High-value transaction without strong verification",
            },
            {
                "name": "MITM Pattern",
                "condition": lambda t: t.get("attacker_modified") is True,
                "risk_score": 100,
                "message": "MITM DETECTED: Transaction data was intercepted and modified",
            },
        ]

    def analyze(self, transaction_data: dict[str, Any]) -> dict[str, Any]:
        risks_found: list[dict[str, Any]] = []
        total_risk = 0

        for rule in self.risk_rules:
            condition: Callable[[dict[str, Any]], bool] = rule["condition"]
            if condition(transaction_data):
                risks_found.append(
                    {
                        "rule": rule["name"],
                        "score": rule["risk_score"],
                        "message": rule["message"],
                    }
                )
                total_risk = max(total_risk, int(rule["risk_score"]))

        if total_risk >= 80:
            risk_level = "CRITICAL"
            recommendation = "BLOCK TRANSACTION - MITM attack suspected"
        elif total_risk >= 50:
            risk_level = "HIGH"
            recommendation = "Require additional verification"
        elif total_risk >= 20:
            risk_level = "MEDIUM"
            recommendation = "Monitor transaction"
        else:
            risk_level = "LOW"
            recommendation = "Proceed normally"

        return {
            "risk_score": total_risk,
            "risk_level": risk_level,
            "risks": risks_found,
            "recommendation": recommendation,
            "is_attack_detected": total_risk >= 80,
        }

    def get_defense_recommendations(self) -> dict[str, list[str]]:
        return {
            "short_term": [
                "Cryptographically bind CVM to transaction signature",
                "Add device attestation requirement",
                "Implement transaction amount limits for NO_CVM",
            ],
            "long_term": [
                "End-to-end encryption between card and bank",
                "Real-time anomaly detection",
                "Stronger cardholder verification enforcement",
            ],
        }
