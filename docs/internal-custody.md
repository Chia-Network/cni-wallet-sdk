# Legacy internal-custody payments

Legacy prefarm custody is a different puzzle family from MIPS/Cloud Wallet vaults
and ClawbackV2. Its clear-signing path deliberately does not call
`parse_vault_transaction` or fall back to interpreting an arbitrary delegated spend.

## Ownership and interfaces

- `chia-sdk-types::puzzles`: pinned module reveals/hashes and typed curry/solution
  schemas. Named state, timelock and filter structures mirror the CLSP fields.
  Existing singleton and standard-puzzle types are reused, not vendored again.
- `chia-sdk-driver::InternalCustodyLayer`: normal `Layer` parsing/construction,
  composable with `SingletonLayer`. Recognizing a layer is not authorization.
- `InternalCustodyPolicy`: validated, bounded public policy/proof data. `new`
  accepts typed configuration; `from_legacy_bytes` imports the existing Python
  RootDerivation format. Both are independent of request JSON or an application.
  `payment_spend` constructs a payment without deposits. `payment_spends` also
  supports explicit deposit absorption, alone or with a payment; its inputs are
  the singleton followed by up to 63 p2-singleton coins sorted by coin ID.
  Neither method adds fees or arbitrary conditions, launches vaults or discovers chain state.
- `parse_internal_custody_payment`: takes a `SpendContext`, supplied policy,
  protocol `CoinSpend` slice, frozen sorted participant keys, `AggSigConstants`
  and an explicit execution cost limit. It returns `VerifiedInternalCustodyPayment`.
- `VerifiedInternalCustodyPayment`: private fields and no public constructor.
  `payment()` exposes typed amounts, destination, input/continuation/pending coins
  and timelocks; `required_signature()` exposes the exact signature requirement.
  `sign_partial` and `verify_partial` enforce membership in its frozen subset.
  `verify_synthetic_offset` checks a public legacy sum hint without trusting it.
- `chia-sdk-signer::RequiredBlsSignature`: reusable aggregate-context
  `sign_partial`/`verify_partial` operations. The condition's public key supplies
  augmentation, rather than the individual participant key. These low-level
  methods do not establish policy membership or user approval.

The mobile signer owns its wire schema, canonical commitment, matching local
key, UniFFI mapping, decimal/address display, device authentication and encrypted
QR. Neither those formats nor app profiles
are part of the SDK API. The same SDK parser can serve a collector or another
Rust wallet without importing the signer app.

## Verification contract

The parser accepts one singleton plus its explicit p2-singleton deposit inputs,
using the unchanged supplied policy and exactly its required selected subset. It recognizes the singleton and
prefarm layers, derives the authorized filter/leaf proofs and synthetic key, then
requires byte-exact agreement with canonical typed reconstruction. It executes
the actual supplied spend under the consensus dialect and explicit cost limit,
without a debug-dialect logging path. It checks the parent/amount assertions,
withdrawal timelock, exact continuation and optional pending-payment outputs,
deposit announcement bindings and single AGG_SIG_ME condition. Every input is
executed under one shared cost budget. Incoming totals use checked arithmetic;
odd totals, duplicate/unordered inputs and mismatched deposits fail closed.
Claim-only requires a zero destination, a positive incoming amount and no outgoing
amount. Its verified `pending_coin` is `None`; it has no completion step. Signature
message construction uses the existing `RequiredBlsSignature::from_condition`.
Unexpected effects or signature modes fail, rather than producing a partial
summary that could enter blind signing.

The caller must bound the allocator used by `SpendContext` and select the
expected network signature-domain constants. The supplied policy is verified
against the exact spend; recognizing its organizational identity or authorizing
that policy independently is an application decision, not a vault-registration
requirement of this parser. Programs are additionally limited to 256 KiB each;
legacy policy decoding bounds total
bytes, key/proof counts and Merkle path depth before allocation. The parser does
not prove that a coin currently exists, is unspent, or that relative timelocks
have elapsed. It does not fetch chain state, authorize a private key, manage a
dependent series, sponsor fees, broadcast or complete payments. Rekeys,
clawbacks, unrelated inputs and additional delegated conditions are unsupported here.

## Payment completion

`InternalCustodyPolicy::completion_spend` constructs the canonical legacy ACH completion spend for an exact pending coin and destination. It checks the pending puzzle hash and positive even amount against the supplied policy, then includes the committed relative timelock. It requires no new custody signature. Callers must check confirmed chain state and elapsed time before broadcasting; construction does not establish readiness.

## Reference and tests

Module sources: Chia-Network/internal-custody revision
`4150dc832a5e66b5ed839974f88d1feb573dcfe2`, Apache-2.0. Provenance and serialized
SHA256 hashes are beside the pinned modules under `chia-sdk-types`.

The public test fixture was generated by the independent Python custody/hsms
implementation with deterministic throwaway keys and short test timelocks.
Production code does not parse the fixture JSON. Tests cover exact puzzle and
solution reconstruction, layer round trips, reference message/destination/coin
agreement, threshold plus synthetic-offset signatures, invalid participant or
augmentation contexts, hidden fee conditions, forged lineage, unsupported
operations, program/cost bounds and malformed policy/proof data.

Run:

```sh
cargo test -p chia-sdk-types -p chia-sdk-signer -p chia-sdk-driver --locked
cargo clippy -p chia-sdk-types -p chia-sdk-signer -p chia-sdk-driver --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

The companion custody-app smoke additionally drives the actual iOS signer through
its SDK adapter and verifies exact partial-signature agreement with hsms plus
acceptance by an isolated Docker simulator. No full custody-operation matrix or
physical device/camera coverage is claimed by these SDK tests.
