# NØNOS NOX payment runtime

NOX is the marketplace's settlement asset on Ethereum mainnet.
The kernel does not know NOX exists. All payment logic lives in
`capsule_payment` and `capsule_wallet` userland; the on-chain
contracts settle local micro-receipts in batches.

```
   app capsule                    capsule_payment
        |                                |
        |   request signature            |
        |------------------------------->|
        |                                |   build receipt preimage
        |                                |   (user, capsule_id, publisher,
        |                                |    amount, nonce, epoch, expiry,
        |                                |    receipt_hash)
        |                                |
        |                                |       capsule_wallet
        |                                |             |
        |                                |---- prompt ->
        |                                |             | user approves
        |                                |   <---  sig --
        |                                |
        |   <----- signed receipt -------|   stored locally; entitlement
        |                                |   live before settlement
        |                                |
        |                ... more receipts accumulate ...
        |                                |
        |                                |   batch threshold reached
        |                                v
        |                       NOXReceiptSettlement (Ethereum mainnet)
        |                                |
        |                                |   batch verified,
        |                                |   nonces monotonic,
        |                                |   fees split via FeeRouter
        |                                v
        |                       on-chain settlement
```

## 1. Why batches, not one tx per fee

A per-event L1 transaction would cost more in gas than most
micro-fees. Instead the OS issues *signed local receipts* that the
publisher accepts immediately, and `capsule_payment` settles them in
groups against `NOXReceiptSettlement`.

Trade-off: between two settlement points the publisher trusts the
user's wallet to be solvent at settlement time. The contract
enforces nonces, epoch boundaries, and a maximum unsettled balance
per (wallet, publisher), so a fraudulent user is bounded.

## 2. Local receipt

```
LocalReceipt {
    user_wallet:  Address
    capsule_id:   Bytes32
    publisher:    Address
    amount:       u128       // wei-equivalent NOX units
    nonce:        u64        // monotonically increasing per (user, publisher)
    epoch:        u64        // settlement epoch boundary
    expiry_ms:    u64        // boot-time clock; rejected if past
    receipt_hash: Bytes32    // BLAKE3 of the canonicalized receipt
    signature:    Bytes      // wallet signature over receipt_hash
}
```

A receipt is valid for the publisher to redeem until `expiry_ms`.
After that the user can re-issue with a fresh nonce.

## 3. On-chain contracts

### `NOXMarketplaceRegistry`
- `capsule_id => { publisher, metadata_uri, manifest_hash, latest_version, status }`
- `status ∈ { active, revoked, deprecated }`
- only the publisher key can update its capsule's manifest hash
- emits `CapsulePublished`, `CapsuleUpdated`, `CapsuleRevoked`

### `NOXEntitlementManager`
- `wallet => capsule_id => Entitlement`
- `Entitlement` is one of: `OneTime`, `Subscription { until }`, `Lifetime`,
  `Credits { remaining }`
- `purchase` accepts payment per entitlement type
- emits events that local indexers (and `capsule_registry`) consume

### `NOXFeeRouter`
- splits each settled fee:
  - publisher share
  - protocol treasury share
  - optional burn / buyback hook
  - optional staking-rewards hook
- splits are configurable by governance, never by an app capsule

### `NOXReceiptSettlement`
- accepts a batch of `LocalReceipt`s
- verifies wallet signatures and nonce monotonicity
- checks `(wallet, publisher, epoch)` against last settled epoch
- routes net amounts through `NOXFeeRouter`
- emits `BatchSettled(batch_root, total_amount)`

### `PublisherRegistry`
- publisher → `{ pubkey, revocation_key, reputation_uri, status }`
- pubkey rotation must be signed by the previous pubkey
- revocation invalidates all future updates and lets the contract
  emit a `PublisherRevoked` event consumed by `capsule_registry`

## 4. Payment modes

| Mode | When it fires | Settlement |
|---|---|---|
| Free | never | none |
| One-time install fee | install time | one receipt at install |
| Subscription | renewal cron in `capsule_payment` | one receipt per period |
| Usage-metered | per usage event the app records | batched receipts |
| Paid update | update install time | one receipt at update |
| Donation | user-triggered | direct on-chain `donate(capsule_id, amount)` |

## 5. Wallet authorisation

The user's wallet (`capsule_wallet`) is the only entity that signs
receipts. App capsules never see the wallet key. The `capsule_payment`
flow:

```
app  -- request_fee(capsule_id, amount) -->  capsule_payment
capsule_payment  -- canonicalize receipt -->  capsule_wallet
capsule_wallet  -- prompt user (if needed) + sign -->  capsule_payment
capsule_payment  -- signed receipt -->  app  (and stores in pending batch)
```

`capsule_wallet` enforces a per-wallet budget: a hard cap on
unsettled outflow that cannot be exceeded between settlements.

## 6. Settlement loop

`capsule_payment` runs a settlement worker that:

1. Picks an epoch that has expired (`now_ms > epoch.end_ms`).
2. Builds a Merkle tree over the receipts whose `epoch == epoch_id`.
3. Submits the batch to `NOXReceiptSettlement`.
4. On `BatchSettled`, removes the batch from local storage and
   updates entitlements in `capsule_registry`.

If submission fails (rpc, gas, reorg), the worker retries with
exponential backoff. Receipts are RAM-only by default; if the user
opts in to durable batching, `capsule_payment` writes to its own
encrypted store, never to a kernel filesystem.

## 7. Replay protection

- Receipt nonces are monotonic per `(wallet, publisher)`.
- Each receipt carries an `epoch` id; the settlement contract
  refuses receipts from a settled epoch.
- The receipt hash is BLAKE3 over the canonical encoding; submitting
  the same hash twice is rejected.

## 8. What the kernel does not do

- does not ship NOX code
- does not ship marketplace code
- does not ship publisher keys
- does not handle ETH RPC
- does not arbitrate fees
- does not see receipts
- does not know which app paid what

The kernel only enforces that a process running an app capsule has
exactly the capabilities its manifest declared and that were granted
at install time. Everything above that is userland.
