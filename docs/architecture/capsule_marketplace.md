# NØNOS Capsule Marketplace architecture

The marketplace lets a NØNOS user discover, install, and run signed
userland capsules. The kernel does not know the marketplace exists.
Discovery, payment, install policy, entitlement checks, and
publisher reputation are userland capsules talking to each other
through `MkIpc*`.

```
+----------------------------------------------------------+
|  chain (Ethereum mainnet)                                |
|    PublisherRegistry   EntitlementManager                |
|    ReceiptSettlement   FeeRouter                         |
+----------------------------------------------------------+
            ^                            ^
            | publisher key sync         | settlement batches
            |                            |
+----------------------------------------------------------+
|  system capsules (CPL=3)                                 |
|    capsule_market     capsule_installer                  |
|    capsule_payment    capsule_wallet                     |
|    capsule_registry   capsule_update                     |
+----------------------------------------------------------+
            |
            |  MkSpawn / MkCapGrant / MkExit
            v
+----------------------------------------------------------+
|  kernel (CPL=0)                                          |
|    syscall gate    capability gate    capsule loader     |
|    IPC primitives  hardware broker    scheduler          |
+----------------------------------------------------------+
            ^
            |  cap-gated MkIpc only
            |
+----------------------------------------------------------+
|  app capsules (CPL=3)                                    |
|    user-installed apps; manifest-bounded caps;           |
|    no ambient access; one process per capsule            |
+----------------------------------------------------------+
```

## 1. Trust boundary

| Layer | What it does | Where it runs |
|---|---|---|
| Kernel | signed capsule load, manifest hash check, capability grants, IPC, address space | `src/` (CPL=0) |
| System capsules | market, install, wallet, payment, registry, update | `userland/capsule_*` (CPL=3) |
| App capsules | the apps the user installs | `userland/<app>` (CPL=3) |
| Settlement | NOX contracts on Ethereum mainnet | off-chain to chain via `capsule_payment` |

The kernel only enforces primitives. It rejects an unsigned capsule,
a manifest whose declared package hash does not match the embedded
binary, or a capability grant outside the manifest's `required` set.
It does not know about NOX, fees, publishers, or the marketplace
index.

## 2. System capsules

### `capsule_market`

Browses and searches the marketplace index. The index is a content-
addressed snapshot fetched from a publisher- or DAO-run mirror. The
capsule validates the snapshot's signature against `PublisherRegistry`
keys it has cached locally. It does not install; it asks
`capsule_installer` over IPC.

### `capsule_installer`

Owns the install pipeline:

1. Fetch the content-addressed package by `package_hash`.
2. Verify the package against the manifest's `package_hash`.
3. Verify the manifest signature against the publisher's pubkey.
4. Verify the publisher's pubkey against `PublisherRegistry`.
5. Resolve the requested capability set. Refuse anything not in
   `required` or `optional`. Prompt the user for `optional`.
6. Ask `capsule_payment` for an entitlement receipt.
7. Register the capsule in the local registry.
8. Hand the verified ELF + capability mask to the kernel via
   `MkSpawn`.

Install lands in the RAM package store by default. Durable install
requires the persistence capability.

### `capsule_wallet`

Holds the user's wallet identity. Signs `NOXAuthorization` payloads
on demand. Never returns a private key over IPC. Hardware wallet
support is a later addition behind the same protocol surface.

### `capsule_payment`

Two roles:

1. **Authoriser**. Takes a fee request from `capsule_installer` or
   from a running app. Asks `capsule_wallet` for a signature. Returns
   a signed local micro-receipt to the caller.
2. **Settler**. Periodically batches accumulated micro-receipts and
   submits them to `NOXReceiptSettlement` on Ethereum mainnet.

A failed settlement does not break running apps; entitlements are
local until a contract event proves they reached the chain.

### `capsule_registry`

Local trusted index cache. Stores:

- Verified publisher keys (pulled from `PublisherRegistry`).
- Revocation lists.
- Local install receipts.
- Capsule manifests for installed apps.

RAM-only by default. Durable mode is opt-in and encrypted with a
key derived from the wallet identity.

### `capsule_update`

Resolves updates. Refuses downgrades unless the user explicitly
selects recovery mode. Refuses publisher-key rotations that are not
signed by the previous key (or by the publisher's revocation key
when applicable).

## 3. Capsule identity

```
capsule_id = BLAKE3(
    manifest_schema_version
 || publisher_pubkey
 || package_hash
 || app_namespace
 || major_version
)
```

Two apps with the same name from different publishers are different
capsule_ids. A major-version bump is a different capsule_id; a minor
version is the same id with a higher version number.

## 4. Capsule manifest

Single signed structure. Schema versioned. Required fields:

```
capsule_id
name
publisher = { name, pubkey, signature_alg }
version = { major, minor, patch }
package_hash    # BLAKE3 of the binary blob
entry_hash      # BLAKE3 of the entry-point ELF
required_caps   # array of CapabilityName
optional_caps   # array of CapabilityName
ipc_endpoints   # array of EndpointDecl
storage_policy  # ram_only | persistent | encrypted_persistent
network_policy  # none | metered | unrestricted
display_policy  # none | windowed | fullscreen
input_policy    # none | keyboard | pointer | both
payment_policy  # free | one_time | subscription | usage_metered
update_policy   # auto | prompt | manual
signatures      # publisher signature, optional reproducible-build attestation
```

The manifest is canonicalized (sorted keys, no whitespace) before
signing.

## 5. Isolation rules

Every installed app:

- runs in its own process and address space
- has its own IPC namespace; endpoints are explicit grants
- has only the capabilities listed in its manifest
- has no ambient filesystem
- has no ambient network
- has no ambient persistence
- has no path to wallet keys
- has no direct hardware access
- a crash kills the app, not the system
- uninstall revokes endpoints and capabilities

## 6. Non-persistence

Default install is RAM-only. Durable install requires:

1. User approval at install time.
2. The persistence capability granted by the user.
3. An explicit `storage_policy = persistent | encrypted_persistent`
   in the manifest.
4. Encrypted package store for `encrypted_persistent`.
5. A wipe policy in the manifest.
6. An uninstall wipe proof.

No app silently persists logs, cache, telemetry, wallet state, or
config.

## 7. Install flow

1. User opens `capsule_market`.
2. Market resolves capsule metadata from its index.
3. `capsule_installer` fetches the content-addressed package.
4. Installer verifies the package hash and the publisher signature.
5. `capsule_payment` returns an entitlement receipt or a NOX micro-
   receipt.
6. Installer prompts the user with the capability set.
7. Installer registers the capsule in `capsule_registry`.
8. Kernel loads the capsule via `MkSpawn` with the granted caps.
9. App runs.

## 8. Operator endpoint contract

The operator (e.g. 0xnox.com) serves the index in two distinct
forms. The OS reads only the binary form; dashboards and the
operator UI read only the JSON form. The two are intentionally
disjoint surfaces — the binary form is what the kernel image's
embedded operator pubkey verifies, and the JSON form is a
convenience for human review.

| Endpoint | Content-Type | Consumer |
|---|---|---|
| `GET /api/v1/marketplace/index` | `application/octet-stream` | OS (`capsule_market` ingest) |
| `GET /api/v1/marketplace/index.json` | `application/json` | dashboard, diff tooling |
| `GET /api/v1/marketplace/signer.pem` | `application/x-pem-file` | review of operator pubkey |

Both index endpoints return the same headers:

```
X-Marketplace-Schema: nonos-marketplace-index-v1
X-Marketplace-Serial: <serial>
ETag: "<serial>"
Cache-Control: public, max-age=300
```

If the operator signing key is unavailable the binary endpoint
returns `503 Service Unavailable`; the JSON endpoint may still
serve a dashboard view of the unsigned source. The OS refuses
the JSON endpoint outright — `capsule_market` only ingests the
binary form, so dashboard drift cannot influence the install
gate.

The binary form is exactly what `nonos_marketplace_abi::encode_index`
produces. The first four bytes are `01 00 00 00`
(`u32 schema_version = 1` little-endian); there is no NOX0
wrapper, no JSON envelope, and no fixed trailer. The
`index_signature` is the trailing `u32`-length-prefixed Ed25519
signature; everything before that prefix is `signed_bytes`.

## 9. Static gates

- No app installs without a manifest.
- No capsule loads without a publisher signature.
- No two capsules share a `capsule_id`.
- No app receives a capability not declared in `required` /
  `optional`.
- No persistence without the persistence capability.
- No wallet-key access from an app capsule.
- No marketplace policy or NOX/payment code in the kernel image.
- No legacy app/runtime roots in the kernel image.
- `tools/Cargo.toml` declares `marketplace-index` and the source
  is present at `tools/src/marketplace_index/main.rs`.
- `marketplace-index` encodes through `nonos_marketplace_abi` —
  no hand-rolled `NOX0`, JSON, or fixed-trailer wire bytes.
- `userland/capsule_market/src/bootstrap_trust/keys.rs` holds the
  baked operator pubkey list; rotation is a kernel image rebuild.
- No `metadata_preview` enum value in `marketplace_abi` without
  a `schema_version` bump (would collide with `rejected = 3`).
- No lowercase `cap_*` capability strings in production
  fixtures; canon is uppercase `CAP_*` from
  `abi/capsule_manifest.schema.json#/$defs/CapName`.

The gates are enforced by `tools/ci/run-static-checks.sh`.
