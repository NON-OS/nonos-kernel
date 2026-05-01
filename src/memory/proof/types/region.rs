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

use super::tags::CapTag;
use crate::memory::addr::PhysAddr;

#[derive(Debug, Clone)]
pub struct MemoryProof {
    pub tag: CapTag,
    pub start_addr: u64,
    pub size: u64,
    pub hash: [u8; 32],
    pub timestamp: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub tag: CapTag,
}
