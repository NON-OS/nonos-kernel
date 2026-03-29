// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
#[derive(Copy, Clone)]
pub struct AcpiInfo {
    pub rsdp: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SmbiosInfo {
    pub entry: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Modules {
    pub ptr: u64,
    pub count: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Timing {
    pub tsc_hz: u64,
    pub unix_epoch_ms: u64,
}
