"""Explicit local/LAN addresses for the owned identity deployment."""

import ipaddress
import json
import re
from pathlib import Path


def validate_network(
    address: str, subnet: str, identity_hostname: str | None = None, public_hostname: str | None = None
):
    host = ipaddress.IPv4Address(address)
    network = ipaddress.IPv4Network(subnet, strict=True)
    private_ranges = [
        ipaddress.IPv4Network(value) for value in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    ]
    if not any(network.subnet_of(private) for private in private_ranges):
        raise ValueError("LAN configuration requires an RFC1918 private IPv4 subnet")
    if host not in network or host in {network.network_address, network.broadcast_address}:
        raise ValueError("The LAN address must be a host inside the specified subnet")
    result = {"address": str(host), "subnet": str(network)}
    for field, value in [("identity_hostname", identity_hostname), ("public_hostname", public_hostname)]:
        if value is None:
            continue
        name = value.lower()
        labels = name.split(".")
        if (
            len(name) > 253
            or len(labels) < 2
            or not re.fullmatch(r"[a-z][a-z0-9-]*", labels[-1])
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            or name.endswith(".localhost")
        ):
            raise ValueError(
                "Public and identity hostnames must be fully qualified DNS names, without a URL or port"
            )
        result[field] = name
    return result


def load_network(runtime: Path):
    path = runtime / "network.json"
    if not path.exists():
        return {"address": "localhost", "subnet": "127.0.0.0/8"}
    values = json.loads(path.read_text())
    return validate_network(
        values["address"], values["subnet"], values.get("identity_hostname"), values.get("public_hostname")
    )


def public_urls(network):
    host = network["address"]
    identity = network.get("identity_hostname", host)
    public = network.get("public_hostname", host)
    return f"https://{public}:19443", f"https://{identity}:18443"
