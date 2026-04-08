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

use super::state::{is_initialized, count, IOAPICS};

#[derive(Debug, Clone)]
pub struct IoApicStatus {
    pub initialized: bool,
    pub count: usize,
    pub total_gsis: u32,
}

pub fn status() -> IoApicStatus {
    let chips = IOAPICS.lock();
    let mut total_gsis = 0u32;
    for chip in chips.iter().flatten() {
        total_gsis += chip.redirs;
    }
    IoApicStatus { initialized: is_initialized(), count: count(), total_gsis }
}
