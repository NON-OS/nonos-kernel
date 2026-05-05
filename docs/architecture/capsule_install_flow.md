# Capsule install flow

End-to-end, from the user clicking "install" in `capsule_market` to
the new capsule running. Every step lists which actor performs it
and which actor it talks to.

## Actors

- `capsule_market`: discovery and UI
- `capsule_installer`: fetch, verify, register, spawn
- `capsule_wallet`: signs payment authorisations
- `capsule_payment`: entitlement check, micro-receipt issuance
- `capsule_registry`: local install record
- kernel: `MkSpawn`, `MkCapGrant`

All inter-capsule communication uses `MkIpcSend` / `MkIpcRecv`. No
shared memory.

## Flow

```
1.  market    -> installer    : Install(capsule_id)
2.  installer -> registry     : LookupPublisherKey(publisher_pubkey)
                  registry    -> installer : key | revoked | unknown
3.  installer -> ext.mirror   : FetchPackage(package_hash)
                  mirror      -> installer : package_bytes
4.  installer                  : verify_package_hash
5.  installer                  : decode_manifest, verify_envelope_signature
6.  installer                  : pick_artifact_for_running_arch
7.  installer                  : verify_artifact_hash, verify_artifact_signature
8.  installer -> payment      : CheckEntitlement(wallet, capsule_id)
                  payment     -> installer : entitled | needs_purchase(amount)
9.  if needs_purchase:
       installer -> payment   : RequestReceipt(capsule_id, amount)
                  payment -> wallet : SignAuthorisation(receipt_preimage)
                  wallet  -> user   : prompt
                  wallet  -> payment: signed_receipt
                  payment -> installer: receipt
10. installer -> user (UI)    : ConfirmCaps(required_caps, optional_caps)
                  user        -> installer : approved_caps
11. installer                  : verify granted ⊆ required ∪ optional
12. installer -> registry     : RegisterInstall(capsule_id, manifest, receipt?)
13. installer -> kernel       : MkSpawn(entry_blob, manifest, granted_caps)
                  kernel       : verify(manifest, package_blob, entry_blob, granted_caps)
                  kernel      -> installer : pid | VerifyError
14. installer -> kernel       : MkCapGrant(pid, endpoint_n) ...
15. installer -> registry     : MarkRunning(capsule_id, pid)
16. installer -> market       : InstallComplete(capsule_id)
```

## Error handling

Each numbered step is fail-closed. Examples:

| Step | Failure | Action |
|---|---|---|
| 2 | publisher revoked | abort install, surface `Revoked` |
| 4 | package hash mismatch | abort install, surface `PackageTampered` |
| 5 | bad envelope signature | abort install, surface `BadSignature` |
| 6 | no arch match | abort install, surface `NoArchMatch` |
| 8 | budget exhausted | prompt user to refund or cancel |
| 11 | granted ⊄ allowed | abort install, surface `CapEscalation` |
| 13 | kernel `VerifyError` | abort install, surface kernel error verbatim |

No partial install state is persisted on failure. The registry
entry is created only on step 12, after every check has passed.

## Non-persistent default

The default install flow stops at step 13; the capsule is loaded
into RAM. It dies on reboot.

Durable install adds a step 12.5:

```
12.5  if manifest.storage_policy ∈ { persistent, encrypted_persistent }
        and granted_caps contains CAP_PERSISTENCE:
        registry -> persistence_store : WriteEncryptedBlob(capsule_id, package_bytes, key)
```

Without `CAP_PERSISTENCE`, the manifest's persistent storage policy
is rejected at step 11.

## Update flow

`capsule_update` runs the same pipeline with two differences:

- It compares the fetched manifest's `version` against the
  registered manifest. Downgrade is rejected unless the user
  selected recovery mode.
- The publisher key on the new manifest must equal the registered
  one (or be a successor signed by the previous key, see
  `PublisherRegistry`).

The atomic apply is: spawn the new capsule, switch the registry's
endpoint table over, signal the old capsule to exit, free its
state. A failed spawn keeps the old capsule running.

## Uninstall

```
installer -> kernel    : MkExit(pid_of(capsule_id))
installer -> registry  : ForgetInstall(capsule_id)
installer -> persist.  : WipeBlob(capsule_id)        (if durable)
```

Uninstall revokes endpoints and capabilities by virtue of the
capsule no longer existing. Capability tokens are tied to a pid; a
dead pid fails every cap check.
