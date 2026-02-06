```

    ##    ##   ######   ##    ##   ######    ######
    ###   ##  ##    ##  ###   ##  ##    ##  ##    ##
    ####  ##  ##    ##  ####  ##  ##    ##  ##
    ## ## ##  ##    ##  ## ## ##  ##    ##   ######
    ##  ####  ##    ##  ##  ####  ##    ##        ##
    ##   ###  ##    ##  ##   ###  ##    ##  ##    ##
    ##    ##   ######   ##    ##   ######    ######

    ██╗  ██╗███████╗██╗   ██╗ ██████╗ ███████╗███╗   ██╗
    ██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝ ██╔════╝████╗  ██║
    █████╔╝ █████╗   ╚████╔╝ ██║  ███╗█████╗  ██╔██╗ ██║
    ██╔═██╗ ██╔══╝    ╚██╔╝  ██║   ██║██╔══╝  ██║╚██╗██║
    ██║  ██╗███████╗   ██║   ╚██████╔╝███████╗██║ ╚████║
    ╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═══╝

```

# nonos-keygen

Ed25519 signing key generator for the NØNOS boot attestation chain.

---

## What This Tool Does

Every kernel that boots on NØNOS must be signed. No signature, no boot. This tool generates the Ed25519 keypairs that make that possible.

When you run keygen, it pulls entropy from your operating system's cryptographic RNG, derives one or more Ed25519 keypairs, writes them to disk with proper permissions, and produces an audit log documenting exactly how and when the keys were created. The secret key bytes are zeroized from memory the moment they hit the filesystem.

The output includes the raw 32-byte seed (what you actually protect), hex and base64 encoded versions for convenience, and the derived public key in all three formats. If you're setting up a multisig scheme, it also generates a signers manifest with fingerprints for each key.

---

## Building

From this directory:

```
cargo build --release
```

The binary lands at `target/release/nonos-keygen`.

---

## Generating Keys

The simplest case is a single signing key for development:

```
./target/release/nonos-keygen \
  --count 1 \
  --out-dir ./keys \
  --allow-write-secrets
```

You'll get `signer1.key` (the 32-byte secret), `signer1.pub.raw` (the 32-byte public key), and encoded versions of both. The secret files are created with mode 0600 so only you can read them.

For a production multisig setup where three of four keyholders must sign:

```
./target/release/nonos-keygen \
  --count 4 \
  --threshold 3 \
  --out-dir ./keys \
  --signers signers.json \
  --operator "your-name@example.com" \
  --allow-write-secrets
```

The `--operator` flag hashes your identity into the generation log for audit purposes. The `signers.json` file lists each signer's public key along with SHA-256 and BLAKE3 fingerprints so you can verify them through independent channels.

If your secrets live in an HSM or air-gapped machine, use `--pub-only` to generate just the public key files and manifest structure:

```
./target/release/nonos-keygen \
  --count 4 \
  --out-dir ./keys \
  --signers signers.json \
  --pub-only
```

---

## Command Line Reference

`--count` or `-c` sets how many keypairs to generate. Defaults to 4.

`--out-dir` or `-o` specifies the output directory. Defaults to `keys`.

`--threshold` sets the number of signatures required in a multisig scheme. Defaults to majority (count/2 + 1).

`--signers` writes the signers manifest to the given path. Without this flag, no manifest is created.

`--id-prefix` changes the naming scheme. Default is `signer`, so you get `signer1`, `signer2`, etc.

`--format` controls which format gets printed to stdout: `raw`, `hex`, or `base64`. All formats are always written to disk regardless.

`--pub-only` skips writing secret key files entirely. Use this when secrets are generated externally.

`--allow-write-secrets` is required to write secret files. The tool refuses without it to prevent accidents.

`--insecure-world-readable` sets file permissions to 0644 instead of 0600. Only use this for throwaway test keys.

`--operator` records an identifier for who ran the generation. Gets hashed in the log for privacy.

---

## Output Structure

After generation, your output directory looks like this:

```
keys/
  signer1.key           # 32-byte secret seed (PROTECT THIS)
  signer1.key.hex       # same, hex encoded
  signer1.key.b64       # same, base64 encoded
  signer1.pub.raw       # 32-byte public key
  signer1.pub.hex       # same, hex encoded
  signer1.pub.b64       # same, base64 encoded
  signers.json          # manifest with fingerprints
  generation_log.json   # audit trail
```

The secret files have mode 0600. The generation log captures the tool version, rustc and cargo versions, git commit if available, a fingerprint of the host machine, the operator hash, timestamp, key count, and threshold. This gives you a complete forensic trail of the key generation event.

---

## Security Considerations

The entropy comes from `OsRng`, which reads `/dev/urandom` on Linux and the equivalent on other platforms. This is the right choice for key generation.

Secret bytes are explicitly zeroized after being written to disk. The `zeroize` crate handles this, overwriting the memory before deallocation. This prevents secrets from lingering in RAM where they could be recovered through memory dumps or cold boot attacks.

All file writes are atomic. The tool writes to a temporary file, calls fsync, then renames to the final path. If power fails mid-write, you get either the complete file or nothing—never a partial key.

For production use, generate keys on an air-gapped machine or use HSM-backed generation. Never commit secret keys to version control. After copying secrets to their final secure location (encrypted storage, HSM), securely erase the originals. The `shred` command on Linux or similar tools can help, though SSDs complicate secure deletion.

---

## Using the Keys

Once you have a signing key, copy it to where the build system expects it:

```
cp keys/signer1.key ../../keys/signing_key_v1.bin
```

Or point the environment variable at it:

```
export NONOS_SIGNING_KEY=/absolute/path/to/signer1.key
```

Then use `sign-kernel` to sign a kernel binary:

```
cd ../sign-kernel
cargo run --release -- \
  --key /path/to/signer1.key \
  --input kernel.bin \
  --output kernel_signed.bin
```

The bootloader build embeds the public key at compile time by reading from `NONOS_SIGNING_KEY` and deriving the public half.

---

## Verifying Fingerprints

When coordinating a multisig ceremony, each keyholder should verify their public key fingerprints through an independent channel. The signers manifest includes both SHA-256 and BLAKE3 hashes:

```
blake3 keys/signer1.pub.raw
sha256sum keys/signer1.pub.raw
```

Compare these against the values in `signers.json`. If they match and everyone confirms their own key, you have a verified signer set.

---

## Dependencies

The cryptography comes from `ed25519-dalek` version 2.1, which implements RFC 8032 Ed25519. Randomness comes from `rand` with `OsRng`. Hashing uses `blake3` and `sha2`. Memory wiping uses `zeroize`. File operations use `tempfile` for atomic writes. Everything else is standard Rust ecosystem tooling.

---

## License

AGPL-3.0-or-later

Copyright 2026 NØNOS Contributors
