"""Safe client-address resolution behind trusted proxies."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from starlette.requests import Request


IPAddress = (
    ipaddress.IPv4Address
    | ipaddress.IPv6Address
)

IPNetwork = (
    ipaddress.IPv4Network
    | ipaddress.IPv6Network
)


def _normalized_fallback(
    value: str | None,
) -> str:
    """Normalize a non-IP peer identifier."""

    if not isinstance(value, str):
        return "unknown"

    normalized = value.strip().lower()

    return normalized or "unknown"


def _parse_ip_address(
    value: str,
) -> IPAddress | None:
    """Parse one strict IPv4 or IPv6 address."""

    candidate = value.strip()

    if not candidate:
        return None

    # Accept bracketed IPv6 addresses.
    if (
        candidate.startswith("[")
        and candidate.endswith("]")
    ):
        candidate = candidate[1:-1]

    try:
        return ipaddress.ip_address(
            candidate
        )
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class ClientAddressResult:
    """Resolved request-client identity."""

    address: str
    peer_address: str
    used_forwarded_header: bool


class TrustedProxyResolver:
    """Resolve clients only through approved proxies."""

    def __init__(
        self,
        trusted_proxy_cidrs: Iterable[str] = (),
    ) -> None:
        networks: list[IPNetwork] = []

        for value in trusted_proxy_cidrs:
            normalized = value.strip()

            if not normalized:
                continue

            try:
                network = (
                    ipaddress.ip_network(
                        normalized,
                        strict=False,
                    )
                )
            except ValueError as error:
                raise ValueError(
                    "Invalid trusted proxy CIDR: "
                    f"{normalized}"
                ) from error

            networks.append(network)

        self.trusted_proxy_networks = tuple(
            networks
        )

    @classmethod
    def from_csv(
        cls,
        value: str | None,
    ) -> TrustedProxyResolver:
        """Create a resolver from comma-separated CIDRs."""

        if not isinstance(value, str):
            return cls()

        return cls(
            part
            for part in value.split(",")
        )

    def _is_trusted(
        self,
        address: IPAddress,
    ) -> bool:
        """Return whether an IP belongs to a trusted network."""

        return any(
            address.version == network.version
            and address in network
            for network
            in self.trusted_proxy_networks
        )

    def resolve(
        self,
        *,
        peer_host: str | None,
        forwarded_for: str | None = None,
    ) -> ClientAddressResult:
        """Resolve a safe client identity."""

        fallback_peer = _normalized_fallback(
            peer_host
        )

        peer_address = (
            _parse_ip_address(fallback_peer)
        )

        # Hostnames and malformed peer values cannot be
        # matched safely against trusted proxy networks.
        if peer_address is None:
            return ClientAddressResult(
                address=fallback_peer,
                peer_address=fallback_peer,
                used_forwarded_header=False,
            )

        normalized_peer = str(peer_address)

        # Forwarding headers are ignored unless the direct
        # network peer is explicitly trusted.
        if not self._is_trusted(peer_address):
            return ClientAddressResult(
                address=normalized_peer,
                peer_address=normalized_peer,
                used_forwarded_header=False,
            )

        if (
            not isinstance(
                forwarded_for,
                str,
            )
            or not forwarded_for.strip()
        ):
            return ClientAddressResult(
                address=normalized_peer,
                peer_address=normalized_peer,
                used_forwarded_header=False,
            )

        forwarded_addresses: list[
            IPAddress
        ] = []

        for raw_value in (
            forwarded_for.split(",")
        ):
            parsed = _parse_ip_address(
                raw_value
            )

            # A malformed chain is ignored completely.
            # Partial parsing could allow ambiguity.
            if parsed is None:
                return ClientAddressResult(
                    address=normalized_peer,
                    peer_address=normalized_peer,
                    used_forwarded_header=False,
                )

            forwarded_addresses.append(
                parsed
            )

        if not forwarded_addresses:
            return ClientAddressResult(
                address=normalized_peer,
                peer_address=normalized_peer,
                used_forwarded_header=False,
            )

        full_chain = [
            *forwarded_addresses,
            peer_address,
        ]

        # Walk from the application outward. Trusted proxy
        # hops are skipped. The nearest untrusted address
        # becomes the client identity.
        for address in reversed(full_chain):
            if self._is_trusted(address):
                continue

            return ClientAddressResult(
                address=str(address),
                peer_address=normalized_peer,
                used_forwarded_header=True,
            )

        # Every address was inside a trusted proxy range.
        # Use the leftmost originating address.
        return ClientAddressResult(
            address=str(full_chain[0]),
            peer_address=normalized_peer,
            used_forwarded_header=True,
        )

def resolve_request_client_address(
    request: Request,
) -> ClientAddressResult:
    """Resolve one request through the configured proxy policy."""

    resolver = getattr(
        request.app.state,
        "trusted_proxy_resolver",
        None,
    )

    if not isinstance(
        resolver,
        TrustedProxyResolver,
    ):
        resolver = TrustedProxyResolver()

    peer_host = (
        request.client.host
        if request.client is not None
        else None
    )

    return resolver.resolve(
        peer_host=peer_host,
        forwarded_for=request.headers.get(
            "X-Forwarded-For"
        ),
    )

