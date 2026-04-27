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

use super::manifest::{AppManifest, AppPermission};
use alloc::vec::Vec;

pub struct AppBuilder {
    manifest: AppManifest,
    binary: Vec<u8>,
    icon: Vec<u8>,
}

impl AppBuilder {
    pub fn new() -> Self {
        Self { manifest: AppManifest::empty(), binary: Vec::new(), icon: Vec::new() }
    }

    pub fn name(mut self, name: &[u8]) -> Self {
        let len = name.len().min(64);
        self.manifest.name[..len].copy_from_slice(&name[..len]);
        self
    }

    pub fn version(mut self, ver: &[u8]) -> Self {
        let len = ver.len().min(16);
        self.manifest.version[..len].copy_from_slice(&ver[..len]);
        self
    }

    pub fn author(mut self, author: &[u8], addr: [u8; 20]) -> Self {
        let len = author.len().min(64);
        self.manifest.author[..len].copy_from_slice(&author[..len]);
        self.manifest.author_addr = addr;
        self
    }

    pub fn description(mut self, desc: &[u8]) -> Self {
        let len = desc.len().min(256);
        self.manifest.description[..len].copy_from_slice(&desc[..len]);
        self
    }

    pub fn price(mut self, nox: u32) -> Self {
        self.manifest.price_nox = nox;
        self
    }
    pub fn category(mut self, cat: u8) -> Self {
        self.manifest.category = cat;
        self
    }

    pub fn permission(mut self, perm: AppPermission) -> Self {
        let cnt = self.manifest.perm_count as usize;
        if cnt < 8 {
            self.manifest.permissions[cnt] = perm;
            self.manifest.perm_count += 1;
        }
        self
    }

    pub fn binary(mut self, data: &[u8]) -> Self {
        self.binary = data.to_vec();
        self.manifest.binary_size = data.len() as u32;
        self
    }

    pub fn icon(mut self, data: &[u8]) -> Self {
        self.icon = data.to_vec();
        self
    }

    pub fn build(self) -> Result<(AppManifest, Vec<u8>, Vec<u8>), &'static str> {
        if self.manifest.name[0] == 0 {
            Err("Name required")
        } else if self.binary.is_empty() {
            Err("Binary required")
        } else {
            Ok((self.manifest, self.binary, self.icon))
        }
    }
}
