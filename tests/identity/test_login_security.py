"""Tests for failed-login tracking and temporary lockout."""

from __future__ import annotations

from src.identity.login_security import (
    LoginSecurityStore,
)
from src.identity.store import IdentityStore


TEST_EMAIL = "analyst@example.com"
TEST_PASSWORD = (
    "Secure-Analyst-Password-2026!"
)


def build_stores(tmp_path):
    """Create isolated identity and security stores."""

    database_path = (
        tmp_path / "identity.db"
    )

    identity_store = IdentityStore(
        database_path
    )

    identity_store.create_account(
        email=TEST_EMAIL,
        display_name="Analyst User",
        password=TEST_PASSWORD,
        role="analyst",
    )

    security_store = LoginSecurityStore(
        database_path,
        max_failed_attempts=5,
        lockout_minutes=15,
    )

    return identity_store, security_store


def test_five_failures_lock_account(
    tmp_path,
):
    identity_store, security_store = (
        build_stores(tmp_path)
    )

    for expected_attempts in range(1, 5):
        state = security_store.record_failure(
            TEST_EMAIL,
            identity_store=identity_store,
        )

        assert (
            state.failed_attempts
            == expected_attempts
        )
        assert state.is_locked is False

    final_state = (
        security_store.record_failure(
            TEST_EMAIL,
            identity_store=identity_store,
        )
    )

    assert final_state.failed_attempts == 5
    assert final_state.locked_until is not None
    assert final_state.is_locked is True

    assert security_store.is_locked(
        TEST_EMAIL
    ) is True


def test_success_resets_failed_attempts(
    tmp_path,
):
    identity_store, security_store = (
        build_stores(tmp_path)
    )

    security_store.record_failure(
        TEST_EMAIL,
        identity_store=identity_store,
    )

    security_store.record_success(
        TEST_EMAIL,
        identity_store=identity_store,
    )

    state = security_store.get_state(
        TEST_EMAIL
    )

    assert state is not None
    assert state.failed_attempts == 0
    assert state.locked_until is None
    assert state.last_failed_at is None
    assert state.is_locked is False


def test_failed_login_is_audited(
    tmp_path,
):
    identity_store, security_store = (
        build_stores(tmp_path)
    )

    security_store.record_failure(
        TEST_EMAIL,
        identity_store=identity_store,
    )

    events = (
        identity_store.list_audit_events(
            limit=10
        )
    )

    failed_events = [
        event
        for event in events
        if event.action == "login_failed"
    ]

    assert len(failed_events) == 1

    event = failed_events[0]

    assert event.actor_email == TEST_EMAIL
    assert event.details[
        "failed_attempts"
    ] == 1
    assert event.details["locked"] is False


def test_password_is_never_logged(
    tmp_path,
):
    identity_store, security_store = (
        build_stores(tmp_path)
    )

    security_store.record_failure(
        TEST_EMAIL,
        identity_store=identity_store,
    )

    events = (
        identity_store.list_audit_events(
            limit=10
        )
    )

    serialized_events = str(
        [
            {
                "action": event.action,
                "details": event.details,
            }
            for event in events
        ]
    )

    assert TEST_PASSWORD not in serialized_events
    assert "password_hash" not in serialized_events


def test_admin_can_clear_account_lockout(
    tmp_path,
):
    identity_store, security_store = (
        build_stores(tmp_path)
    )

    admin = identity_store.create_account(
        email="admin@example.com",
        display_name="Admin User",
        password=(
            "Secure-Admin-Password-2026!"
        ),
        role="admin",
    )

    for _ in range(5):
        security_store.record_failure(
            TEST_EMAIL,
            identity_store=identity_store,
        )

    assert security_store.is_locked(
        TEST_EMAIL
    )

    previous_state = (
        security_store.unlock_account(
            TEST_EMAIL,
            identity_store=identity_store,
            actor_user_id=admin.user_id,
            actor_email=admin.email,
        )
    )

    assert previous_state.failed_attempts == 5
    assert previous_state.is_locked is True

    assert security_store.get_state(
        TEST_EMAIL
    ) is None

    events = identity_store.list_audit_events(
        limit=20
    )

    unlock_events = [
        event
        for event in events
        if event.action == "account_unlocked"
    ]

    assert len(unlock_events) == 1
    assert unlock_events[0].actor_email == (
        admin.email
    )
    assert unlock_events[0].details[
        "target_email"
    ] == TEST_EMAIL


def test_unlocked_account_is_required(
    tmp_path,
):
    identity_store, security_store = (
        build_stores(tmp_path)
    )

    admin = identity_store.create_account(
        email="admin@example.com",
        display_name="Admin User",
        password=(
            "Secure-Admin-Password-2026!"
        ),
        role="admin",
    )

    import pytest

    with pytest.raises(
        ValueError,
        match="not currently locked",
    ):
        security_store.unlock_account(
            TEST_EMAIL,
            identity_store=identity_store,
            actor_user_id=admin.user_id,
            actor_email=admin.email,
        )
