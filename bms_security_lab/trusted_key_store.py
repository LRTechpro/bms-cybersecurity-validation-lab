from dataclasses import dataclass, replace


@dataclass(frozen=True)
class TrustedPublicKey:
    """Public verification key metadata; private keys are never stored here."""

    signer_id: str
    public_key_bytes: bytes
    valid_from_s: float
    valid_until_s: float
    revoked: bool = False

    def __post_init__(self) -> None:
        if not self.signer_id.strip():
            raise ValueError("Signer identity is required.")
        if len(self.public_key_bytes) != 32:
            raise ValueError("Ed25519 public key must contain 32 raw bytes.")
        if self.valid_from_s < 0 or self.valid_until_s <= self.valid_from_s:
            raise ValueError("Public-key validity interval is invalid.")


class TrustedKeyStore:
    """Model protected trusted-public-key storage and lifecycle policy."""

    def __init__(self, keys: tuple[TrustedPublicKey, ...] = ()) -> None:
        self._keys: dict[str, TrustedPublicKey] = {}
        self.audit_log: list[str] = []
        for key in keys:
            self.add_initial_key(key)

    def add_initial_key(self, key: TrustedPublicKey) -> None:
        if key.signer_id in self._keys:
            raise ValueError(f"Signer {key.signer_id!r} already exists.")
        self._keys[key.signer_id] = key

    def get_current_key(
        self,
        signer_id: str,
        now_s: float,
    ) -> TrustedPublicKey | None:
        key = self._keys.get(signer_id)
        if key is None or key.revoked:
            return None
        if not key.valid_from_s <= now_s <= key.valid_until_s:
            return None
        return key

    def is_known(self, signer_id: str) -> bool:
        return signer_id in self._keys

    def is_revoked(self, signer_id: str) -> bool:
        key = self._keys.get(signer_id)
        return bool(key and key.revoked)

    def revoke(self, signer_id: str, actor: str) -> None:
        if not actor.strip():
            raise ValueError("Authorized actor is required for revocation.")
        key = self._require_key(signer_id)
        self._keys[signer_id] = replace(key, revoked=True)
        self.audit_log.append(f"REVOKE:{signer_id}:{actor}")

    def rotate(
        self,
        new_key: TrustedPublicKey,
        actor: str,
        authenticated: bool,
    ) -> None:
        """Accept a new public key only through an authorized trust update."""
        if not authenticated or not actor.strip():
            raise PermissionError("Authenticated actor is required for key rotation.")
        if new_key.signer_id in self._keys:
            raise ValueError("Rotated signer identity must be new.")
        self._keys[new_key.signer_id] = new_key
        self.audit_log.append(f"ROTATE:{new_key.signer_id}:{actor}")

    def _require_key(self, signer_id: str) -> TrustedPublicKey:
        try:
            return self._keys[signer_id]
        except KeyError as error:
            raise KeyError(f"Unknown signer {signer_id!r}.") from error
