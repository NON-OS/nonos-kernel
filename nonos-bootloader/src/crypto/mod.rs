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

mod keys;
pub mod keystore_v2;
pub mod sig;
mod verify;

pub use sig::{
    get_key_fingerprint, get_minimum_version, get_nonos_key, get_nonos_key_id, init_nonos_keys,
    init_production_keys, is_initialized, key_count, perform_crypto_self_test,
    revoke_key_by_pubkey, set_minimum_version, validate_key, verify_signature, CertificateStatus,
    KeyStatus, RevocationReason, SignatureStatus, SignatureVerifier, NONOS_SIGNING_KEY,
};
