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

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};

use crate::error::CliError;

pub struct OperatorKey {
    signing: SigningKey,
}

impl OperatorKey {
    pub fn from_file(path: &Path) -> Result<Self, CliError> {
        let raw = std::fs::read(path)?;
        Self::from_seed_bytes(&raw, "key file")
    }

    pub fn from_env(var: &str) -> Result<Self, CliError> {
        let value = std::env::var(var)
            .map_err(|_| CliError::KeyError(format!("env var {var} not set")))?;
        let bytes = hex::decode(value.trim())
            .map_err(|e| CliError::KeyError(format!("env var {var}: hex: {e}")))?;
        Self::from_seed_bytes(&bytes, var)
    }

    fn from_seed_bytes(bytes: &[u8], origin: &str) -> Result<Self, CliError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(CliError::KeyError(format!(
                "{origin}: expected {SECRET_KEY_LENGTH}-byte seed, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        seed.copy_from_slice(bytes);
        Ok(OperatorKey { signing: SigningKey::from_bytes(&seed) })
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}
