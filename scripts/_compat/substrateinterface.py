"""Minimal stand-in for the legacy `substrate-interface` package.

`upstream/scripts/register_miner.py` does `from substrateinterface import Keypair`
to sign the submission. That package is dead weight under Bittensor 11, which
ships `bittensor_core` instead and does not depend on it — so the import fails
and submission dies before any network call, with a message telling you to
`pip install substrate-interface`. Installing it would drag a second, older
scalecodec/py-substrate stack in next to the SDK we actually use.

`bittensor_core.Keypair` is the same sr25519 implementation with the same API;
the only difference that matters here is that it takes seed bytes where the old
package took a hex string. Verified against wallet `default/sn76`:
`create_from_seed` reproduces ss58 `5HgUJ5SF…M8WtL` exactly, and sign/verify
round-trips a 64-byte signature.

Put this directory on PYTHONPATH ahead of site-packages; nothing else is needed.
If a real `substrate-interface` is ever installed, delete this file — it exists
only to satisfy that one import.
"""
from __future__ import annotations

from bittensor_core import Keypair as _Keypair

__all__ = ["Keypair", "KeypairType"]


class KeypairType:
    ED25519 = 0
    SR25519 = 1
    ECDSA = 2


class Keypair:
    """Constructors only. `bittensor_core.Keypair` is a pyo3 type and cannot be
    subclassed, so these return the native object — `sign`, `verify` and
    `ss58_address` are then the real implementation, not a wrapper."""

    @staticmethod
    def create_from_seed(seed, **kwargs):
        if isinstance(seed, str):
            seed = bytes.fromhex(seed[2:] if seed.startswith("0x") else seed)
        return _Keypair.create_from_seed(seed, **kwargs)

    @staticmethod
    def create_from_private_key(private_key, **kwargs):
        if isinstance(private_key, (bytes, bytearray)):
            private_key = "0x" + bytes(private_key).hex()
        return _Keypair.create_from_private_key(private_key, **kwargs)

    @staticmethod
    def create_from_mnemonic(mnemonic, **kwargs):
        return _Keypair.create_from_mnemonic(mnemonic, **kwargs)

    @staticmethod
    def create_from_uri(uri, **kwargs):
        return _Keypair.create_from_uri(uri, **kwargs)
