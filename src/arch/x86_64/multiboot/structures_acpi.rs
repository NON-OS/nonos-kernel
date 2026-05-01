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
use crate::memory::addr::PhysAddr;

#[derive(Debug, Clone)]
pub struct AcpiRsdp {
    pub revision: u8,
    pub rsdp_address: PhysAddr,
    pub is_xsdt: bool,
}

#[derive(Debug, Clone)]
pub struct SmbiosInfo {
    pub major: u8,
    pub minor: u8,
    pub tables: alloc::vec::Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub type_: u32,
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub num_pages: u64,
    pub attribute: u64,
}
