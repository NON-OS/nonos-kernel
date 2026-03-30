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

use super::state::RemoteAttestationClient;

impl RemoteAttestationClient {
    pub fn add_trusted_key(&mut self, public_key: [u8; 32]) {
        if !self.trusted_keys.contains(&public_key) {
            self.trusted_keys.push(public_key);
        }
    }

    pub fn remove_trusted_key(&mut self, public_key: &[u8; 32]) {
        self.trusted_keys.retain(|k| k != public_key);
    }

    pub fn is_key_trusted(&self, public_key: &[u8; 32]) -> bool {
        self.trusted_keys.contains(public_key)
    }

    pub fn trusted_key_count(&self) -> usize {
        self.trusted_keys.len()
    }

    pub fn get_current_nonce(&self) -> [u8; 32] {
        self.current_nonce
    }
}
