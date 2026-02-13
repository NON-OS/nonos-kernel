// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

pub use super::keys::{
    add_key, add_key_versioned, derive_keyid, get_build_timestamp, get_key_fingerprint,
    get_minimum_version, get_nonos_key, get_nonos_key_id, init_nonos_keys, init_production_keys,
    is_initialized, key_count, revoke_key_by_pubkey, set_minimum_version, validate_key, KeyId,
    KeyStatus, KeyStore, RevocationEntry, RevocationReason, KEYSTORE, MAX_KEYS, MAX_REVOKED,
    NONOS_SIGNING_KEY, PK_LEN,
};

pub use super::verify::{
    perform_crypto_self_test, verify_signature, verify_signature_bytes, verify_signature_full,
    CapsuleMetadata, CertificateStatus, SignatureStatus, SignatureVerifier, VerifyError, SIG_LEN,
};
