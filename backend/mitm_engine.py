from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class MITMAttack:
    def __init__(self) -> None:
        self.active = False
        self.modifications: list[dict[str, Any]] = []

    def activate(self) -> dict[str, str]:
        self.active = True
        self.modifications = []
        return {"status": "activated", "message": "MITM attack active"}

    def deactivate(self) -> dict[str, str]:
        self.active = False
        return {"status": "deactivated", "message": "MITM attack disabled"}

    def _stamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def modify_cvm(self, original_cvm: str) -> str:
        if not self.active:
            return original_cvm

        self.modifications.append(
            {
                "field": "CVM",
                "original": original_cvm,
                "modified": "NO_VERIFICATION",
                "timestamp": self._stamp(),
            }
        )
        return "NO_VERIFICATION"

    def modify_device_verified(self, original_value: bool) -> bool:
        if not self.active:
            return original_value

        self.modifications.append(
            {
                "field": "device_verified",
                "original": original_value,
                "modified": True,
                "timestamp": self._stamp(),
            }
        )
        return True

    def modify_card_response(self, original_response: dict[str, Any]) -> dict[str, Any]:
        if not self.active:
            return original_response

        modified = {
            **original_response,
            "cvm": self.modify_cvm(original_response.get("cvm", "UNKNOWN")),
            "device_verified": self.modify_device_verified(bool(original_response.get("device_verified", False))),
            "attacker_modified": True,
        }
        self.modifications.append(
            {
                "field": "full_response",
                "modified": modified,
                "timestamp": self._stamp(),
            }
        )
        return modified

    def get_attack_log(self) -> dict[str, Any]:
        return {
            "attack_active": self.active,
            "modifications": self.modifications,
            "total_lies": len(self.modifications),
        }
