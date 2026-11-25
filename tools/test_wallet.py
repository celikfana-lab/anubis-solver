#!/usr/bin/env python3
"""
A test bitcoin wallet: derive the address in tests/wallet/test-wallet.json.

This exists so the `meatrider` payout path has a *real* address to demonstrate
with, instead of the `bcrt1qmeatridertestaddress` placeholder the gate tests
used to carry. It is a wallet in the only sense that matters here -- a secp256k1
key and the addresses derived from it -- and nothing more: no transaction is
built, no node is contacted, no coin is tracked.

    python3 tools/test_wallet.py --check     # does the JSON match its own key?
    python3 tools/test_wallet.py --show      # addresses, WIF and the URI
    python3 tools/test_wallet.py --new       # a fresh key, for a new fixture
    python3 tools/test_wallet.py --new --out ~/w/MyName.json --label MyName
                                             # a wallet of your own, outside git
    python3 tools/test_wallet.py --selftest  # the published key-1 vectors

DO NOT SEND BITCOIN TO THESE ADDRESSES. The private key is in the repository, on
purpose, so that the fixture can be checked by anyone. Every satoshi sent to the
mainnet address is spendable by every reader of this repository, and none of it
reaches the person who wrote the tests. The testnet address is where the tests
point: testnet coins are worthless by design, which is exactly the property a
test fixture wants.

The derivation is P2PKH with a compressed public key (BIP-32's default shape,
no derivation path): HASH160 = RIPEMD160(SHA256(pubkey)), then Base58Check.
Standard library only -- secp256k1 is 40 lines of the curve below.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WALLET = ROOT / "tests" / "wallet" / "test-wallet.json"

# secp256k1, as both Bitcoin and every other elliptic-curve thing define it.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

MAINNET = {"p2pkh": 0x00, "wif": 0x80}
TESTNET = {"p2pkh": 0x6F, "wif": 0xEF}   # regtest uses the same version bytes


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] % P * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) % P * pow((q[0] - p[0]) % P, -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return x, (lam * (p[0] - x) - p[1]) % P


def point_mul(k: int):
    result, addend = None, G
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def pubkey_compressed(priv: bytes) -> bytes:
    """33 bytes: the parity of y in the first byte, then x."""
    k = int.from_bytes(priv, "big")
    if not 0 < k < N:
        raise ValueError("private key is outside secp256k1's order")
    x, y = point_mul(k)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def b58check(payload: bytes) -> str:
    """Base58 with the four-byte double-SHA256 checksum, leading zeros intact."""
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = b""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem:rem + 1] + out
    zeros = len(data) - len(data.lstrip(b"\0"))
    return (B58[0:1] * zeros + out).decode()


def b58check_decode(text: str) -> bytes:
    n = 0
    for ch in text.encode():
        n = n * 58 + B58.index(bytes([ch]))
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    zeros = len(text) - len(text.lstrip("1"))
    data = b"\0" * zeros + raw
    if len(data) < 5:
        raise ValueError("too short")
    payload, check = data[:-4], data[-4:]
    want = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if check != want:
        raise ValueError("checksum does not match")
    return payload


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def address(priv: bytes, net: dict) -> str:
    return b58check(bytes([net["p2pkh"]]) + hash160(pubkey_compressed(priv)))


def wif(priv: bytes, net: dict) -> str:
    return b58check(bytes([net["wif"]]) + priv + b"\x01")   # compressed


def wif_to_priv(text: str) -> bytes:
    payload = b58check_decode(text)
    if len(payload) != 34 or payload[-1] != 1:
        raise ValueError("not a compressed-key WIF")
    return payload[1:33]


def derive(priv_hex: str) -> dict:
    priv = bytes.fromhex(priv_hex)
    return {
        "pubkey_compressed": pubkey_compressed(priv).hex(),
        "hash160": hash160(pubkey_compressed(priv)).hex(),
        "mainnet": {"address": address(priv, MAINNET), "wif": wif(priv, MAINNET)},
        "testnet": {"address": address(priv, TESTNET), "wif": wif(priv, TESTNET)},
    }


def selftest() -> int:
    """The published "private key 1" vectors: if these fail, nothing upstream did."""
    fail = 0
    priv = (1).to_bytes(32, "big")
    d = derive(priv.hex())
    # The four published vectors for the private key 1 (compressed): its public
    # key point, its mainnet WIF, and the two P2PKH addresses. The testnet WIF is
    # not in that set -- WIFs of small keys share a long prefix, which is how
    # copying one from memory goes wrong -- so both WIFs and both addresses are
    # checked by decoding them back instead.
    cases = [
        ("pubkey", d["pubkey_compressed"],
         "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        ("mainnet wif", d["mainnet"]["wif"],
         "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("mainnet address", d["mainnet"]["address"],
         "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        ("testnet address", d["testnet"]["address"],
         "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"),
    ]
    for label, got, want in cases:
        if got != want:
            print(f"  FAIL {label}: {got} != {want}")
            fail += 1
    for net in ("mainnet", "testnet"):
        if wif_to_priv(d[net]["wif"]) != priv:
            print(f"  FAIL the {net} WIF does not decode back to the key")
            fail += 1
        if b58check_decode(d[net]["address"])[1:] != hash160(pubkey_compressed(priv)):
            print(f"  FAIL the {net} address does not decode back to the hash160")
            fail += 1
    checks = len(cases) + 4
    print(f"key-1 vectors: {checks} checks, "
          f"{'all ok' if fail == 0 else f'{fail} failures above'}")
    return 1 if fail else 0


def load(path: Path | None = None) -> dict:
    return json.loads((path or WALLET).read_text())


def check(path: Path | None = None) -> int:
    target = path or WALLET    # `path` is shadowed by the loop below
    doc = load(path)
    got = derive(doc["private_key_hex"])
    bad = 0
    for path, want in (("pubkey_compressed", got["pubkey_compressed"]),
                       ("hash160", got["hash160"]),
                       ("mainnet.address", got["mainnet"]["address"]),
                       ("mainnet.wif", got["mainnet"]["wif"]),
                       ("testnet.address", got["testnet"]["address"]),
                       ("testnet.wif", got["testnet"]["wif"])):
        node = doc
        for part in path.split("."):
            node = node[part]
        if node != want:
            print(f"  FAIL {path}: recorded {node}, derived {want}")
            bad += 1
        else:
            print(f"  ok   {path}: {node}")
    if doc.get("testnet", {}).get("address") != got["testnet"]["address"]:
        bad += 1
    try:
        target = target.relative_to(ROOT)
    except ValueError:
        pass
    print(f"{target}: {'ok' if bad == 0 else f'{bad} wrong'}")
    return 1 if bad else 0


def show(path: Path | None = None) -> None:
    doc = load(path)
    d = derive(doc["private_key_hex"])
    print(f"network   address                              wif")
    for net in ("mainnet", "testnet"):
        print(f"{net:9s} {d[net]['address']:36s} {d[net]['wif']}")
    print("\nno transaction is built and no node is contacted: this is a key and")
    print("the strings derived from it, which is all the payout path needs.")
    print(f"the gate would publish: bitcoin:{d['testnet']['address']}"
          f"?amount=0.00001334&label=meatrider-test")


def new(out: Path | None = None, label: str = "") -> int:
    priv = secrets.token_bytes(32)
    while not 0 < int.from_bytes(priv, "big") < N:
        priv = secrets.token_bytes(32)
    d = derive(priv.hex())
    if out is not None:
        return new_named(out, label, priv, d)
    doc = {
        "purpose": ("the fixture the gate tests use as the meatrider payout address: it "
                    "exercises --meatrider-pay, the pay JSON and the receipt derivation. It "
                    "is not a destination and no code in this repository ever signs a "
                    "transaction."),
        "warning": [
            "TEST WALLET. The private key below is published on purpose so the",
            "fixture can be verified by anyone. NEVER send bitcoin to the mainnet",
            "address: every satoshi sent there is spendable by every reader of this",
            "repository, and none of it reaches the author. The tests use the",
            "testnet address, where coins are worthless by design.",
        ],
        "private_key_hex": priv.hex(),
        "pubkey_compressed": d["pubkey_compressed"],
        "hash160": d["hash160"],
        "mainnet": {"address": d["mainnet"]["address"], "wif": d["mainnet"]["wif"],
                    "use": "do not send bitcoin here"},
        "testnet": {"address": d["testnet"]["address"], "wif": d["testnet"]["wif"],
                    "use": "the tests point here"},
        "derivation": "P2PKH, compressed public key, no derivation path",
        "generated_by": "tools/test_wallet.py --new",
    }
    WALLET.parent.mkdir(parents=True, exist_ok=True)
    WALLET.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {WALLET}")
    print(f"  testnet {d['testnet']['address']}")
    print(f"  mainnet {d['mainnet']['address']}   <- never send bitcoin here")
    return 0



def new_named(out: Path, label: str, priv: bytes, d: dict) -> int:
    """A wallet of one's own, in a file the caller names -- keep it out of git.

    The fixture wallet in tests/wallet/ is public on purpose and therefore
    worthless by construction. This is the other kind: a key that exists only in
    the file written here.
    """
    name = label or out.stem
    doc = {
        "label": name,
        "purpose": f"wallet {name!r}, generated by tools/test_wallet.py --out",
        "warning": [
            "PRIVATE KEY. This file is the wallet: anyone holding it can spend",
            "everything sent to these addresses. Do not commit it, do not paste it",
            "into a chat, and keep a backup somewhere that is not this machine.",
            "The mainnet address is only worth using if this file stays private.",
        ],
        "private_key_hex": priv.hex(),
        "pubkey_compressed": d["pubkey_compressed"],
        "hash160": d["hash160"],
        "mainnet": {"address": d["mainnet"]["address"], "wif": d["mainnet"]["wif"],
                    "use": "real bitcoin -- only if this file is private"},
        "testnet": {"address": d["testnet"]["address"], "wif": d["testnet"]["wif"],
                    "use": "worthless coins, for testing the payout path"},
        "derivation": "P2PKH, compressed public key, no derivation path",
        "generated_by": "tools/test_wallet.py --new --out --label",
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        out.parent.chmod(0o700)
    except OSError:
        pass
    fd = out.open("w")
    try:
        fd.write(json.dumps(doc, indent=2) + "\n")
    finally:
        fd.close()
    try:
        out.chmod(0o600)
    except OSError:
        pass
    print(f"wrote {out}  (mode 600, keep it private)")
    print(f"  label   {name}")
    print(f"  testnet {d['testnet']['address']}")
    print(f"  mainnet {d['mainnet']['address']}")
    print(f"  uri     bitcoin:{d['testnet']['address']}?label={name}")
    print("the WIF is in the file, not printed here on purpose.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="derive from the recorded key and compare with the recorded addresses")
    ap.add_argument("--show", action="store_true", help="print the addresses and the URI")
    ap.add_argument("--new", action="store_true", help="generate a fresh key into the JSON")
    ap.add_argument("--out", type=Path, default=None,
                    help="with --new: write the wallet here instead of the fixture")
    ap.add_argument("--label", default="",
                    help="with --new --out: the wallet's name, recorded in the file")
    ap.add_argument("--wallet", type=Path, default=None,
                    help="with --check/--show: read this file instead of the fixture")
    ap.add_argument("--selftest", action="store_true",
                    help="check the derivation against the published private-key-1 vectors")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.new:
        if args.out is not None and args.out.exists():
            print(f"error: {args.out} exists; refusing to overwrite a wallet",
                  file=sys.stderr)
            return 1
        return new(args.out, args.label)
    wallet = args.wallet or WALLET
    if not wallet.exists():
        print(f"error: {wallet} does not exist; run --new", file=sys.stderr)
        return 1
    if args.show:
        show(args.wallet)
        return 0
    rc = check(args.wallet)
    selftest()
    return rc


if __name__ == "__main__":
    sys.exit(main())
