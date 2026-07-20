"""Command-line administration for SOC analyst accounts."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from src.identity.models import ALLOWED_ANALYST_ROLES
from src.identity.store import IdentityStore


def create_account(
    store: IdentityStore,
    args: argparse.Namespace,
) -> None:
    """Create an analyst account securely."""

    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass(
        "Confirm password: "
    )

    if password != confirmation:
        raise SystemExit(
            "Passwords do not match."
        )

    account = store.create_account(
        email=args.email,
        display_name=args.name,
        password=password,
        role=args.role,
    )

    print("Account created successfully")
    print("Email:", account.email)
    print("Name:", account.display_name)
    print("Role:", account.role)
    print("User ID:", account.user_id)


def list_accounts(
    store: IdentityStore,
) -> None:
    """Display all analyst accounts."""

    accounts = store.list_accounts()

    if not accounts:
        print("No analyst accounts found.")
        return

    for account in accounts:
        account_state = (
            "active"
            if account.is_active
            else "disabled"
        )

        print(
            f"{account.email} | "
            f"{account.display_name} | "
            f"{account.role} | "
            f"{account_state}"
        )


def main() -> None:
    """Run the account-management command."""

    parser = argparse.ArgumentParser(
        description=(
            "Manage AI SOC Copilot analyst accounts."
        )
    )

    parser.add_argument(
        "--database",
        required=True,
        help="Path to the SOC SQLite database.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    create_parser = subparsers.add_parser(
        "create",
        help="Create an analyst account.",
    )

    create_parser.add_argument(
        "--email",
        required=True,
    )

    create_parser.add_argument(
        "--name",
        required=True,
    )

    create_parser.add_argument(
        "--role",
        choices=sorted(ALLOWED_ANALYST_ROLES),
        default="analyst",
    )

    subparsers.add_parser(
        "list",
        help="List analyst accounts.",
    )

    args = parser.parse_args()

    store = IdentityStore(
        Path(args.database)
    )

    if args.command == "create":
        create_account(store, args)
    elif args.command == "list":
        list_accounts(store)


if __name__ == "__main__":
    main()
