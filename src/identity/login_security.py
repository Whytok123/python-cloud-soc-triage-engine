"""Failed-login tracking and temporary account lockout."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from src.identity.store import IdentityStore


DEFAULT_MAX_FAILED_ATTEMPTS = 5
DEFAULT_LOCKOUT_MINUTES = 15


def _utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""

    return datetime.now(timezone.utc)


def _normalize_email(email: str) -> str:
    """Normalize an attempted login email."""

    if not isinstance(email, str):
        return ""

    return email.strip().lower()


def _parse_timestamp(
    value: str | None,
) -> datetime | None:
    """Parse an ISO-8601 timestamp."""

    if not value:
        return None

    normalized = value

    if normalized.endswith("Z"):
        normalized = (
            normalized[:-1] + "+00:00"
        )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class LoginSecurityState:
    """Current failed-login state for an email."""

    email: str
    failed_attempts: int
    locked_until: str | None
    last_failed_at: str | None
    updated_at: str

    @property
    def is_locked(self) -> bool:
        """Return whether lockout is active."""

        lock_expiration = _parse_timestamp(
            self.locked_until
        )

        return bool(
            lock_expiration
            and lock_expiration > _utc_now()
        )


class LoginSecurityStore:
    """SQLite-backed failed-login protection."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        max_failed_attempts: int = (
            DEFAULT_MAX_FAILED_ATTEMPTS
        ),
        lockout_minutes: int = (
            DEFAULT_LOCKOUT_MINUTES
        ),
    ) -> None:
        if max_failed_attempts < 1:
            raise ValueError(
                "max_failed_attempts must be "
                "at least one."
            )

        if lockout_minutes < 1:
            raise ValueError(
                "lockout_minutes must be "
                "at least one."
            )

        self.database_path = Path(
            database_path
        )

        self.max_failed_attempts = (
            max_failed_attempts
        )

        self.lockout_minutes = (
            lockout_minutes
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize_database()

    def _connect(
        self,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = sqlite3.Row

        return connection

    def _initialize_database(
        self,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                identity_login_security (
                    email TEXT PRIMARY KEY
                        COLLATE NOCASE,
                    failed_attempts INTEGER
                        NOT NULL DEFAULT 0,
                    locked_until TEXT,
                    last_failed_at TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _row_to_state(
        row: sqlite3.Row,
    ) -> LoginSecurityState:
        return LoginSecurityState(
            email=row["email"],
            failed_attempts=int(
                row["failed_attempts"]
            ),
            locked_until=row["locked_until"],
            last_failed_at=row[
                "last_failed_at"
            ],
            updated_at=row["updated_at"],
        )

    def get_state(
        self,
        email: str,
    ) -> LoginSecurityState | None:
        normalized_email = _normalize_email(
            email
        )

        if not normalized_email:
            return None

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    email,
                    failed_attempts,
                    locked_until,
                    last_failed_at,
                    updated_at
                FROM identity_login_security
                WHERE email = ?
                """,
                (normalized_email,),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_state(row)

    def is_locked(
        self,
        email: str,
    ) -> bool:
        state = self.get_state(email)

        if state is None:
            return False

        if state.is_locked:
            return True

        if state.locked_until is not None:
            self.clear_state(email)

        return False

    def record_failure(
        self,
        email: str,
        *,
        identity_store: IdentityStore,
    ) -> LoginSecurityState:
        normalized_email = (
            _normalize_email(email)
            or "unknown"
        )

        now = _utc_now()
        timestamp = now.isoformat()

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT failed_attempts
                FROM identity_login_security
                WHERE email = ?
                """,
                (normalized_email,),
            ).fetchone()

            previous_attempts = (
                int(row["failed_attempts"])
                if row is not None
                else 0
            )

            failed_attempts = (
                previous_attempts + 1
            )

            locked_until = None

            if failed_attempts >= (
                self.max_failed_attempts
            ):
                locked_until = (
                    now
                    + timedelta(
                        minutes=self.lockout_minutes
                    )
                ).isoformat()

            connection.execute(
                """
                INSERT INTO
                    identity_login_security (
                        email,
                        failed_attempts,
                        locked_until,
                        last_failed_at,
                        updated_at
                    )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(email)
                DO UPDATE SET
                    failed_attempts =
                        excluded.failed_attempts,
                    locked_until =
                        excluded.locked_until,
                    last_failed_at =
                        excluded.last_failed_at,
                    updated_at =
                        excluded.updated_at
                """,
                (
                    normalized_email,
                    failed_attempts,
                    locked_until,
                    timestamp,
                    timestamp,
                ),
            )

        account = identity_store.get_by_email(
            normalized_email
        )

        target_user_id = (
            account.user_id
            if account is not None
            else None
        )

        identity_store.record_audit_event(
            actor_user_id=target_user_id,
            actor_email=normalized_email,
            target_user_id=target_user_id,
            action="login_failed",
            details={
                "failed_attempts": (
                    failed_attempts
                ),
                "locked": (
                    locked_until is not None
                ),
            },
        )

        if locked_until is not None:
            identity_store.record_audit_event(
                actor_user_id=target_user_id,
                actor_email=normalized_email,
                target_user_id=target_user_id,
                action="account_locked",
                details={
                    "failed_attempts": (
                        failed_attempts
                    ),
                    "locked_until": (
                        locked_until
                    ),
                    "method": (
                        "automatic_login_protection"
                    ),
                },
            )

        state = self.get_state(
            normalized_email
        )

        if state is None:
            raise RuntimeError(
                "Failed-login state was not saved."
            )

        return state

    def record_success(
        self,
        email: str,
        *,
        identity_store: IdentityStore,
    ) -> None:
        normalized_email = _normalize_email(
            email
        )

        if not normalized_email:
            return

        timestamp = _utc_now().isoformat()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO
                    identity_login_security (
                        email,
                        failed_attempts,
                        locked_until,
                        last_failed_at,
                        updated_at
                    )
                VALUES (?, 0, NULL, NULL, ?)
                ON CONFLICT(email)
                DO UPDATE SET
                    failed_attempts = 0,
                    locked_until = NULL,
                    last_failed_at = NULL,
                    updated_at =
                        excluded.updated_at
                """,
                (
                    normalized_email,
                    timestamp,
                ),
            )

        account = identity_store.get_by_email(
            normalized_email
        )

        identity_store.record_audit_event(
            actor_user_id=(
                account.user_id
                if account is not None
                else None
            ),
            actor_email=normalized_email,
            target_user_id=(
                account.user_id
                if account is not None
                else None
            ),
            action="login_succeeded",
            details={
                "method": "password",
            },
        )

    def record_blocked_attempt(
        self,
        email: str,
        *,
        identity_store: IdentityStore,
    ) -> None:
        normalized_email = (
            _normalize_email(email)
            or "unknown"
        )

        state = self.get_state(
            normalized_email
        )

        account = identity_store.get_by_email(
            normalized_email
        )

        identity_store.record_audit_event(
            actor_user_id=(
                account.user_id
                if account is not None
                else None
            ),
            actor_email=normalized_email,
            target_user_id=(
                account.user_id
                if account is not None
                else None
            ),
            action="login_blocked",
            details={
                "locked_until": (
                    state.locked_until
                    if state is not None
                    else None
                ),
            },
        )

    def clear_state(
        self,
        email: str,
    ) -> None:
        normalized_email = _normalize_email(
            email
        )

        if not normalized_email:
            return

        with self._connect() as connection:
            connection.execute(
                """
                DELETE FROM identity_login_security
                WHERE email = ?
                """,
                (normalized_email,),
            )

    def list_states(
        self,
        *,
        include_clean: bool = False,
    ) -> list[LoginSecurityState]:
        """List current login-security states."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    email,
                    failed_attempts,
                    locked_until,
                    last_failed_at,
                    updated_at
                FROM identity_login_security
                ORDER BY
                    failed_attempts DESC,
                    email ASC
                """
            ).fetchall()

        states: list[LoginSecurityState] = []

        for row in rows:
            state = self._row_to_state(row)

            if (
                state.locked_until is not None
                and not state.is_locked
            ):
                self.clear_state(state.email)
                continue

            has_security_activity = (
                state.failed_attempts > 0
                or state.is_locked
            )

            if (
                include_clean
                or has_security_activity
            ):
                states.append(state)

        return states

    def unlock_account(
        self,
        email: str,
        *,
        identity_store: IdentityStore,
        actor_user_id: str,
        actor_email: str,
    ) -> LoginSecurityState:
        """Clear an account lockout as an administrator."""

        normalized_email = _normalize_email(
            email
        )

        if not normalized_email:
            raise ValueError(
                "A valid account email is required."
            )

        account = identity_store.get_by_email(
            normalized_email
        )

        if account is None:
            raise KeyError(
                f"Unknown account: {normalized_email}"
            )

        previous_state = self.get_state(
            normalized_email
        )

        if (
            previous_state is None
            or not previous_state.is_locked
        ):
            raise ValueError(
                "The account is not currently locked."
            )

        self.clear_state(normalized_email)

        identity_store.record_audit_event(
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            target_user_id=account.user_id,
            action="account_unlocked",
            details={
                "method": "administrator",
                "target_email": account.email,
                "previous_failed_attempts": (
                    previous_state.failed_attempts
                ),
                "previous_locked_until": (
                    previous_state.locked_until
                ),
            },
        )

        return previous_state
