// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use super::EncryptionError;

pub fn derive_capability_key(identity: &str, capability_mask: u64) -> Result<[u8; 32], EncryptionError> {
    if identity.is_empty() {
        return Err(EncryptionError::KeyDerivationFailed);
    }

    let context = b"NONOS_IPC_CAPABILITY_KEY_V1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(context);
    hasher.update(identity.as_bytes());
    hasher.update(&capability_mask.to_le_bytes());

    let hash_result = hasher.finalize();
    let mut cap_key = [0u8; 32];
    cap_key.copy_from_slice(hash_result.as_bytes());

    Ok(cap_key)
}