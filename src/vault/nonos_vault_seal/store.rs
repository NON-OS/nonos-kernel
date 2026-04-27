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

extern crate alloc;
use super::types::SealedSecret;
use alloc::vec::Vec;
use spin::Mutex;

pub struct VaultSealStore {
    pub(super) sealed: Mutex<Vec<SealedSecret>>,
}

impl VaultSealStore {
    pub const fn new() -> Self {
        Self { sealed: Mutex::new(Vec::new()) }
    }

    pub fn list_sealed(&self) -> Vec<SealedSecret> {
        self.sealed.lock().clone()
    }
}

pub static VAULT_SEAL_STORE: VaultSealStore = VaultSealStore::new();
