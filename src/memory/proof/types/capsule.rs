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

use super::region::MemoryRegion;
use super::tags::CapTag;

#[derive(Debug, Clone, Copy)]
pub struct CapsulePermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub sealed: bool,
}

#[derive(Debug, Clone)]
pub struct CryptographicCapsule {
    pub capsule_id: u64,
    pub memory_region: MemoryRegion,
    pub integrity_hash: [u8; 32],
    pub access_key: [u8; 32],
    pub permissions: CapsulePermissions,
    pub creation_time: u64,
}

#[derive(Debug)]
pub struct CapsuleInfo {
    pub id: u64,
    pub start: u64,
    pub end: u64,
    pub tag: CapTag,
    pub sealed: bool,
    pub creation_time: u64,
}
