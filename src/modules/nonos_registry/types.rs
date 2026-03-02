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


use crate::modules::nonos_manifest::ModuleManifest;

#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub manifest: ModuleManifest,
    pub hash: [u8; 32],
    pub attested: bool,
    pub registered_at: u64,
}

impl RegistryEntry {
    pub fn new(manifest: ModuleManifest, attested: bool) -> Self {
        Self {
            hash: manifest.hash,
            manifest,
            attested,
            registered_at: 0, // Will be set by registry on insertion
        }
    }

    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.registered_at = timestamp;
        self
    }
}
