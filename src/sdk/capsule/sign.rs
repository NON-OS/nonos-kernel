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

pub struct SigningKey {
    secret: [u8; 32],
    public: [u8; 32],
}

impl SigningKey {
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        crate::crypto::random::fill_bytes(&mut secret);
        let public = crate::crypto::ed25519::pubkey_from_secret(&secret);
        Self { secret, public }
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        let public = crate::crypto::ed25519::pubkey_from_secret(&secret);
        Self { secret, public }
    }

    pub fn public(&self) -> &[u8; 32] { &self.public }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        crate::crypto::ed25519::sign(&self.secret, data)
    }
}

pub fn verify_signature(pubkey: &[u8; 32], data: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 { return false; }
    crate::crypto::ed25519::verify(pubkey, data, sig)
}

pub fn load_key_from_file(path: &str) -> Option<SigningKey> {
    let data = crate::fs::ramfs::read_file(path).ok()?;
    if data.len() < 32 { return None; }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&data[..32]);
    Some(SigningKey::from_secret(secret))
}

pub fn save_key_to_file(key: &SigningKey, path: &str) -> bool {
    crate::fs::ramfs::write_file(path, &key.secret).is_ok()
}
