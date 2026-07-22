"""Trusted-proxy client-address tests."""

from __future__ import annotations

import pytest

from src.api.client_address import (
    TrustedProxyResolver,
)


def test_untrusted_peer_cannot_spoof_forwarded_ip():
    resolver = TrustedProxyResolver()

    result = resolver.resolve(
        peer_host="192.0.2.10",
        forwarded_for="198.51.100.25",
    )

    assert result.address == "192.0.2.10"
    assert result.peer_address == "192.0.2.10"

    assert (
        result.used_forwarded_header
        is False
    )


def test_trusted_proxy_can_supply_client_ip():
    resolver = TrustedProxyResolver(
        ["10.0.0.0/8"]
    )

    result = resolver.resolve(
        peer_host="10.0.0.10",
        forwarded_for="198.51.100.25",
    )

    assert result.address == (
        "198.51.100.25"
    )

    assert result.peer_address == (
        "10.0.0.10"
    )

    assert (
        result.used_forwarded_header
        is True
    )


def test_nearest_untrusted_address_is_selected():
    resolver = TrustedProxyResolver(
        [
            "10.0.0.0/8",
            "172.16.0.0/12",
        ]
    )

    result = resolver.resolve(
        peer_host="10.0.0.10",
        forwarded_for=(
            "203.0.113.90, "
            "198.51.100.45, "
            "172.16.5.20"
        ),
    )

    # The rightmost trusted proxy is skipped.
    # The nearest untrusted address is selected.
    assert result.address == (
        "198.51.100.45"
    )


def test_malformed_forwarding_chain_is_ignored():
    resolver = TrustedProxyResolver(
        ["10.0.0.0/8"]
    )

    result = resolver.resolve(
        peer_host="10.0.0.10",
        forwarded_for=(
            "198.51.100.25, invalid-address"
        ),
    )

    assert result.address == "10.0.0.10"

    assert (
        result.used_forwarded_header
        is False
    )


def test_ipv6_addresses_are_supported():
    resolver = TrustedProxyResolver(
        ["2001:db8:100::/48"]
    )

    result = resolver.resolve(
        peer_host="2001:db8:100::10",
        forwarded_for="2001:db8:200::25",
    )

    assert result.address == (
        "2001:db8:200::25"
    )

    assert (
        result.used_forwarded_header
        is True
    )


def test_non_ip_test_client_uses_safe_fallback():
    resolver = TrustedProxyResolver(
        ["127.0.0.0/8"]
    )

    result = resolver.resolve(
        peer_host="testclient",
        forwarded_for="198.51.100.25",
    )

    assert result.address == "testclient"

    assert (
        result.used_forwarded_header
        is False
    )


def test_invalid_proxy_configuration_is_rejected():
    with pytest.raises(
        ValueError,
        match="Invalid trusted proxy CIDR",
    ):
        TrustedProxyResolver(
            ["not-a-network"]
        )


def test_csv_configuration_is_parsed():
    resolver = TrustedProxyResolver.from_csv(
        "10.0.0.0/8, 192.168.0.0/16"
    )

    assert len(
        resolver.trusted_proxy_networks
    ) == 2

    result = resolver.resolve(
        peer_host="192.168.1.10",
        forwarded_for="203.0.113.25",
    )

    assert result.address == (
        "203.0.113.25"
    )
