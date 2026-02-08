# NØNOS ZK Embed Tool

Generates Rust code for embedding Groth16 verifying keys into the bootloader. Takes your circuit's program ID and verifying key, derives the PROGRAM_HASH, normalizes the VK to canonical format, and outputs paste-ready code.

Status: Used in the NØNOS release build process.

---

## What it does

1. Takes your program/circuit identifier (string, hex, or file)
2. Derives a 32-byte PROGRAM_HASH using BLAKE3 with domain separation
3. Loads your Groth16 VK, validates it, re-serializes to canonical compressed bytes
4. Outputs Rust constants and a lookup function ready to paste into the bootloader

The bootloader uses the PROGRAM_HASH to look up the correct VK at runtime when verifying ZK proofs during boot.

---

## Build

```
cargo build --release -p zk-embed
```

---

## Usage

```
zk-embed \
  --program-id-str "zkmod-attestation-program-v1" \
  --vk path/to/verifying_key.bin \
  --const-prefix ATTEST_V1
```

This prints Rust code to stdout. To write to a file:

```
zk-embed \
  --program-id-str "zkmod-attestation-program-v1" \
  --vk path/to/verifying_key.bin \
  --const-prefix ATTEST_V1 \
  --out zk_consts.rs
```

---

## Options

| Flag | Description |
|------|-------------|
| `--program-id-str STR` | Program ID as UTF-8 string |
| `--program-id-hex HEX` | Program ID as hex bytes |
| `--program-id-file PATH` | Program ID from raw file |
| `--vk PATH` | Path to Groth16 verifying key (arkworks format) |
| `--const-prefix NAME` | Prefix for generated constants (default: PROGRAM) |
| `--ds-program STR` | Domain separator (default: NONOS:ZK:PROGRAM:v1) |
| `--out PATH` | Write output to file instead of stdout |

Only one of `--program-id-str`, `--program-id-hex`, or `--program-id-file` can be used.

---

## Output format

The tool generates code like this:

```rust
// --- paste into src/zk/zkverify.rs ---
// DS: NONOS:ZK:PROGRAM:v1

pub const PROGRAM_HASH_ATTEST_V1: [u8; 32] = [
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    // ... 32 bytes total
];

pub const VK_ATTEST_V1_BLS12_381_GROTH16: &[u8] = &[
    0x97, 0xf1, 0xd3, 0xa7, 0x30, 0x19, 0x7f, 0xc0,
    // ... ~580 bytes for BLS12-381 Groth16 VK
];

#[cfg(feature = "zk-groth16")]
fn program_vk_lookup(program_hash: &[u8; 32]) -> Option<&'static [u8]> {
    if ct_eq32(program_hash, &PROGRAM_HASH_ATTEST_V1) {
        return Some(VK_ATTEST_V1_BLS12_381_GROTH16);
    }
    None
}
```

---

## Embedding in the bootloader

1. Run zk-embed to generate the constants
2. Paste the output into `nonos-boot/src/zk/zkverify.rs`
3. Build with ZK features enabled:

```
cargo build --release --features zk-groth16,zk-vk-provisioned
```

The `zk-vk-provisioned` feature is a compile-time guard that fails the build if no VKs are embedded. This prevents accidentally shipping a bootloader that can't verify proofs.

---

## VK format

The tool accepts arkworks `CanonicalSerialize` format for BLS12-381 Groth16 verifying keys. It tries both compressed and uncompressed formats automatically.

Output is always canonical compressed, the exact byte representation the bootloader's verifier expects.

If you have a VK in a different format, you'll need to convert it using arkworks first.

---

## Domain separation

PROGRAM_HASH is derived as:

```
BLAKE3::derive_key("NONOS:ZK:PROGRAM:v1", program_id_bytes)
```

The domain separator ensures program hashes are unique to NØNOS and can't collide with hashes from other systems. Don't change it unless you also update the prover side.

---

## Multiple circuits

For multiple circuits, run zk-embed once per circuit with different prefixes:

```
zk-embed --program-id-str "circuit-a" --vk vk_a.bin --const-prefix CIRCUIT_A
zk-embed --program-id-str "circuit-b" --vk vk_b.bin --const-prefix CIRCUIT_B
```

Then combine the lookup function:

```rust
fn program_vk_lookup(program_hash: &[u8; 32]) -> Option<&'static [u8]> {
    if ct_eq32(program_hash, &PROGRAM_HASH_CIRCUIT_A) {
        return Some(VK_CIRCUIT_A_BLS12_381_GROTH16);
    }
    if ct_eq32(program_hash, &PROGRAM_HASH_CIRCUIT_B) {
        return Some(VK_CIRCUIT_B_BLS12_381_GROTH16);
    }
    None
}
```

---

## Troubleshooting

**"provide exactly one of --program-id-str | --program-id-hex | --program-id-file"**
- You must specify exactly one program ID source

**"failed to deserialize verifying key"**
- VK file is not valid arkworks format
- Check the file isn't corrupted or truncated
- Ensure it's a BLS12-381 Groth16 VK (not BN254 or another curve)

**"verifying key file is empty"**
- Check the path is correct

**Build fails with "zk-vk-provisioned but no VKs"**
- You need to add the generated constants to zkverify.rs before building

---

## License

AGPL-3.0
