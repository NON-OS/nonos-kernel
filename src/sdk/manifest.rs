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

#[derive(Clone, Copy, PartialEq)]
pub enum AppPermission {
    Storage,
    Network,
    Wallet,
    Camera,
    Microphone,
    Filesystem,
    Notifications,
    Background,
}

#[derive(Clone)]
pub struct AppManifest {
    pub id: [u8; 32],
    pub name: [u8; 64],
    pub version: [u8; 16],
    pub author: [u8; 64],
    pub author_addr: [u8; 20],
    pub description: [u8; 256],
    pub category: u8,
    pub price_nox: u32,
    pub permissions: [AppPermission; 8],
    pub perm_count: u8,
    pub icon_hash: [u8; 32],
    pub binary_hash: [u8; 32],
    pub binary_size: u32,
    pub min_os_version: [u8; 8],
    pub signature: [u8; 65],
}

impl AppManifest {
    pub const fn empty() -> Self {
        Self {
            id: [0; 32],
            name: [0; 64],
            version: [0; 16],
            author: [0; 64],
            author_addr: [0; 20],
            description: [0; 256],
            category: 0,
            price_nox: 0,
            permissions: [AppPermission::Storage; 8],
            perm_count: 0,
            icon_hash: [0; 32],
            binary_hash: [0; 32],
            binary_size: 0,
            min_os_version: [0; 8],
            signature: [0; 65],
        }
    }

    pub fn has_permission(&self, p: AppPermission) -> bool {
        for i in 0..self.perm_count as usize {
            if self.permissions[i] == p {
                return true;
            }
        }
        false
    }
}
