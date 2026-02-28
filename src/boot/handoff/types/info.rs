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

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AcpiInfo {
    pub rsdp: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SmbiosInfo {
    pub entry: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Module {
    pub base: u64,
    pub size: u64,
    pub kind: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Modules {
    pub ptr: u64,
    pub count: u32,
    pub reserved: u32,
}

impl Modules {
    // SAFETY: Caller must ensure ptr points to valid Module array
    pub unsafe fn modules(&self) -> &[Module] { unsafe {
        if self.ptr == 0 || self.count == 0 {
            return &[];
        }
        core::slice::from_raw_parts(self.ptr as *const Module, self.count as usize)
    }}
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Timing {
    pub tsc_hz: u64,
    pub unix_epoch_ms: u64,
}
