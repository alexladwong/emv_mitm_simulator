from __future__ import annotations

import hashlib
from typing import Any


class RSACrypto:
    """
    Simplified RSA for educational simulation.
    Not intended for production cryptography.
    """

    def __init__(self) -> None:
        self.public_key = {"e": 65537, "n": 3233}
        self.private_key = {"d": 2753, "n": 3233}

    def _message_digest(self, message: str, modulus: int) -> int:
        return int(hashlib.sha256(message.encode()).hexdigest(), 16) % modulus

    def sign(self, message: str, private_key: dict[str, int]) -> int:
        digest = self._message_digest(message, private_key["n"])
        return pow(digest, private_key["d"], private_key["n"])

    def verify(self, message: str, signature: int, public_key: dict[str, int]) -> bool:
        digest = self._message_digest(message, public_key["n"])
        decrypted = pow(signature, public_key["e"], public_key["n"])
        return digest == decrypted

    def demonstrate_attack(self) -> dict[str, Any]:
        original_data = "CVM=PIN_VERIFIED&amount=10000&device_verified=True"
        signature = self.sign(original_data, self.private_key)
        modified_data = "CVM=NO_VERIFICATION&amount=10000&device_verified=True"

        return {
            "original_data": original_data,
            "modified_data": modified_data,
            "signature": signature,
            "original_signature_valid": self.verify(original_data, signature, self.public_key),
            "modified_signature_valid": self.verify(modified_data, signature, self.public_key),
            "explanation": "The signature checks out only for what was originally signed.",
            "vulnerability": "In some EMV flows, CVM and device verification context are not cryptographically bound.",
        }

    def demonstrate_emv_vulnerability(self) -> dict[str, Any]:
        return {
            "signed_fields": ["amount", "currency", "date"],
            "unsigned_fields": ["CVM", "device_verified", "terminal_capabilities"],
            "vulnerability": "CVM and device_verified can be outside the signed payload in weak designs.",
            "attack": "A MITM can alter unsigned fields without invalidating signed transaction elements.",
        }
