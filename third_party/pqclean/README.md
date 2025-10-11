PQClean vendored sources for ML-KEM (Kyber) — production use

This directory contains a pinned copy of PQClean’s constant-time “clean” C implementations:

- crypto_kem/mlkem512/clean/...
- crypto_kem/mlkem768/clean/...
- crypto_kem/mlkem1024/clean/...

Upstream:
- https://github.com/PQClean/PQClean
- Commit (pin this to a specific audited hash): <PUT-PINNED-COMMIT-HASH-HERE>

Licensing:
- PQClean files are CC0/MIT/Apache-2.0 (per-file). Include the upstream LICENSE files in this vendor tree.

Notes:
- We compile only the needed sources for the selected parameter set (default: mlkem768).
- No runtime CPU features required; constant-time “clean” C is used.
- Do not modify PQClean sources unless applying vetted security patches; document any patches here.
