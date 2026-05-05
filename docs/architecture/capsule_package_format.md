# NØNOS capsule package format

A capsule package is a content-addressed bundle. The bundle carries
one manifest and one or more architecture-specific artifacts. The
kernel never sees the bundle; the userland installer
(`capsule_installer`) selects the artifact for the running
architecture and hands the kernel the manifest plus the ELF.

## 1. Layout

```
package.bin
+--- header
|       magic        = "NONOSCAP"
|       version      = 1
|       artifact_count
|
+--- manifest
|       length (u32 BE)
|       canonical_manifest_bytes      // see capsule_manifest schema
|
+--- artifact[i]                        i in 0..artifact_count
|       target_triple_len (u8)
|       target_triple                 // e.g. "x86_64-nonos"
|       abi_version       (u32 BE)    // capsule ABI version this artifact targets
|       kernel_abi_min    (u32 BE)    // minimum kernel ABI it accepts
|       artifact_hash     ([u8; 32])  // BLAKE3 of the artifact bytes
|       artifact_signature ([u8; 64]) // publisher signature over the canonical artifact descriptor
|       artifact_len      (u32 BE)
|       artifact_bytes
```

The header + manifest + every artifact's descriptor (everything except
the artifact byte payloads) form the *signed envelope*. The
publisher signs the envelope hash; the installer recomputes the hash
when verifying.

## 2. Hashes

- `package_hash` in the manifest = BLAKE3 of the entire package bytes.
- `entry_hash` in the manifest = BLAKE3 of the chosen artifact's
  bytes after the installer has selected one.
- `artifact_hash` per artifact = BLAKE3 of that artifact's bytes
  alone.

The installer:

1. Verifies `BLAKE3(package_bytes) == manifest.package_hash`.
2. Picks the artifact whose `target_triple` matches the kernel's
   reported arch and whose `kernel_abi_min` is satisfied.
3. Verifies `BLAKE3(picked.artifact_bytes) == picked.artifact_hash`.
4. Verifies `BLAKE3(picked.artifact_bytes) == manifest.entry_hash`
   (the manifest's entry hash always points at the artifact the
   installer is about to load on the running arch; there is one
   manifest per arch family if entry hashes differ across arches,
   see §4).

## 3. Signatures

Every artifact descriptor is signed independently. This lets a
publisher add or remove arch artifacts without re-signing the whole
package; only the changed artifact's descriptor needs a new
signature, alongside a manifest revision that reflects the new
`entry_hash`.

The package envelope itself is signed by the publisher key. The
two signatures are independent: the installer requires both to be
valid against the same publisher pubkey for the artifact it picks.

## 4. Multi-arch rule

A package MUST contain at least one artifact. It MAY contain any of:

- `x86_64-nonos`
- `aarch64-nonos`
- `riscv64-nonos`

The installer selects strictly by exact triple match. There is no
emulation fallback: if no artifact matches the running kernel arch,
install fails with `NoArchMatch`. An emulator capsule, if installed,
is just another userland capsule the user authorized; the kernel
never invokes it as a fallback.

When `entry_hash` would differ across arches (the usual case, since
each arch has a different ELF), the publisher publishes one manifest
*per arch family* with the same `capsule_id` (because `capsule_id`
hashes `package_hash`, which hashes the bundle, which is shared) and
different `entry_hash`. The installer picks the manifest whose
`entry_hash` matches the artifact it picked.

A simpler scheme (one manifest with a list of `entry_hash` per
arch) is rejected: it adds attack surface by carrying multiple
entry hashes in one signed structure. The chosen scheme is one
manifest per arch family.

## 5. Reproducible build attestation (optional)

If present, an artifact carries an extra descriptor:

```
build_attestation_len (u16 BE)
build_attestation_bytes              // CBOR or sigstore bundle
```

The kernel does not consult this. The installer surfaces it to the
user / market UI. Publishers without a reproducible build pipeline
omit the attestation entirely.

## 6. What this format excludes

- No metadata strings (description, screenshots, icon). Those live
  on the marketplace index, not in the signed package.
- No price / payment fields. Payment is enforced by `capsule_payment`
  out of band.
- No dependencies. Capsules are self-contained; if an app needs
  another capsule, it asks via IPC at runtime, and the user grants
  the endpoint.
- No update channel. Updates are resolved by `capsule_update`
  pulling fresh manifests from the marketplace.

## 7. Versioning

The package format itself is versioned via the header `version`
field. The manifest schema is versioned via
`MANIFEST_SCHEMA_VERSION` (see `src/security/capsule_manifest`). The
two are independent: the package layout can evolve without a
manifest schema change and vice versa.
