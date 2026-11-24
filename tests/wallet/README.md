# The test wallet

`test-wallet.json` is a **fixture, not a destination**: a real secp256k1 key with
the addresses derived from it, committed so the `meatrider` payout path has
something concrete to demonstrate — `--meatrider-pay`, the `pay` JSON, the
receipt derivation, and the `bitcoin:` URI the page hands to a wallet.

**Do not send bitcoin to these addresses.** The private key is in the JSON on
purpose, so anyone can re-derive the address and check that the fixture is what
it claims to be; the same property means anyone can spend whatever arrives.
Nothing in this repository signs a transaction, watches the chain, or moves
coins: the tier publishes an address and an amount, and the operator confirms the
payment by hand.

| network | address | where it is used |
|---|---|---|
| testnet | `myMBYAqh4iHXRmPdiarpUvk9t1rMJB7wKd` | the gate tests and the docs |
| mainnet | `1JqEF7kiFgrGeev211tSf1Xq22FePvCYj9` | nowhere — do not send bitcoin here |

The tests point at the **testnet** address, where coins are worthless by design,
which is the property a fixture wants. `betterAnusbis/test-meatrider-gate.sh`
reads the address out of the JSON rather than carrying a copy, and
`python3 ../tools/test_wallet.py --check` derives it from the key, so a fixture
that drifts from its own key fails the suite.

## Checking it

```bash
python3 tools/test_wallet.py --check      # derive from the key, compare with the JSON
python3 tools/test_wallet.py --show       # addresses, WIFs, and the bitcoin: URI
python3 tools/test_wallet.py --selftest   # the published private-key-1 vectors
python3 tools/test_wallet.py --new        # a fresh key, if the fixture is ever burned
```

`--check` runs the self-test too: four published vectors for the private key `1`
(its compressed public key, its mainnet WIF, and both P2PKH addresses) plus
decoding both WIFs and both addresses back to the key and the hash160. If the
curve, Base58Check or RIPEMD160 in the tool were wrong, those fail before the
fixture does.

## What "wallet" means here

A key and the strings derived from it: P2PKH, compressed public key, no
derivation path, no HD seed. Standard library only — the secp256k1 arithmetic is
forty lines in `tools/test_wallet.py` rather than a dependency. That is all the
payout path needs, because it only ever *prints* an address.

For a real deployment, generate a key on a machine that is not this one, keep it
out of the repository, and pass its address to `--meatrider-pay`; see
[`MIGRATE.md`](../../MIGRATE.md) and the `meatrider` section of
[`README.md`](../../README.md#meatrider-proof-of-work-priced-in-bitcoin).
