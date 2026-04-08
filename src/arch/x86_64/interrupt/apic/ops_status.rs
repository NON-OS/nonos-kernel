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

use super::state::{is_initialized, is_x2apic, supports_tsc_deadline};
use super::ops_core::{id, get_tpr, version, max_lvt};

#[derive(Debug, Clone)]
pub struct ApicStatus {
    pub initialized: bool,
    pub x2apic: bool,
    pub tsc_deadline: bool,
    pub id: u32,
    pub version: u32,
    pub max_lvt: u8,
    pub tpr: u8,
}

pub fn status() -> ApicStatus {
    ApicStatus {
        initialized: is_initialized(),
        x2apic: is_x2apic(),
        tsc_deadline: supports_tsc_deadline(),
        id: id(),
        version: if is_initialized() { version() } else { 0 },
        max_lvt: if is_initialized() { max_lvt() } else { 0 },
        tpr: get_tpr(),
    }
}
