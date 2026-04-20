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

pub fn derive_shared_secret(sender: &str, receiver: &str, master_key: &[u8; 32]) -> Result<[u8; 32], EncryptionError> {
    if sender.is_empty() || receiver.is_empty() {
        return Err(EncryptionError::KeyDerivationFailed);
    }

    let (first, second) = if sender < receiver {
        (sender, receiver)
    } else {
        (receiver, sender)
    };

    let context = b"NONOS_IPC_SHARED_SECRET_V1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(context);
    hasher.update(master_key);
    hasher.update(first.as_bytes());
    hasher.update(b"|");
    hasher.update(second.as_bytes());

    let hash_result = hasher.finalize();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(hash_result.as_bytes());

    Ok(secret)
}