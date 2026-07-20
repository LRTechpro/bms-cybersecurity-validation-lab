"""Authorization rules for simulated BMS message sources."""


class AuthorizationPolicy:
    """Store trusted source identities and their allowed actions."""

    def __init__(
        self,
        known_source_ids: set[int],
        permissions_by_source: dict[int, set[str]],
        revoked_source_ids: set[int] | None = None,
    ) -> None:
        # Copy collections so outside code cannot silently alter the policy.
        self._known_source_ids = set(known_source_ids)
        self._permissions_by_source = {
            source_id: set(actions)
            for source_id, actions in permissions_by_source.items()
        }
        self._revoked_source_ids = set(revoked_source_ids or set())

        # Permission and revocation entries must belong to known identities.
        unknown_permission_sources = (
            set(self._permissions_by_source)
            - self._known_source_ids
        )
        if unknown_permission_sources:
            raise ValueError(
                "Permissions contain unknown source IDs: "
                f"{sorted(unknown_permission_sources)}"
            )

        unknown_revoked_sources = (
            self._revoked_source_ids
            - self._known_source_ids
        )
        if unknown_revoked_sources:
            raise ValueError(
                "Revoked list contains unknown source IDs: "
                f"{sorted(unknown_revoked_sources)}"
            )

    def is_known_source(self, source_id: int) -> bool:
        """Return whether the source identity is recognized."""

        return source_id in self._known_source_ids

    def is_revoked(self, source_id: int) -> bool:
        """Return whether a recognized source has been revoked."""

        return source_id in self._revoked_source_ids

    def is_authorized(self, source_id: int, action: str) -> bool:
        """Return whether the source may perform the requested action."""

        # Unknown and revoked sources never receive permission.
        if (
            not self.is_known_source(source_id)
            or self.is_revoked(source_id)
        ):
            return False

        allowed_actions = self._permissions_by_source.get(
            source_id,
            set(),
        )
        return action in allowed_actions

    def revoke_source(self, source_id: int) -> None:
        """Revoke a known source identity."""

        if not self.is_known_source(source_id):
            raise ValueError(
                f"Cannot revoke unknown source 0x{source_id:X}."
            )

        self._revoked_source_ids.add(source_id)

    def restore_source(self, source_id: int) -> None:
        """Remove a known source from the revoked set."""

        if not self.is_known_source(source_id):
            raise ValueError(
                f"Cannot restore unknown source 0x{source_id:X}."
            )

        self._revoked_source_ids.discard(source_id)
