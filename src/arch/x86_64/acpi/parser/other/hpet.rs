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

use core::ptr;

use super::super::state::TableRegistry;
use crate::arch::x86_64::acpi::tables::{Hpet, SIG_HPET};

pub fn parse_hpet(registry: &mut TableRegistry) {
    if let Some(&addr) = registry.tables.get(&SIG_HPET) {
        unsafe {
            let hpet = ptr::read_volatile(addr as *const Hpet);
            if hpet.is_valid() {
                registry.data.hpet_address = Some(hpet.address());
            }
        }
    }
}
