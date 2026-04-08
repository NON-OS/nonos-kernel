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

use super::types::IsoFlags;
use super::state::{IoApicChip, IOAPICS, ISO};

pub(super) fn iso_flags_for(gsi: u32) -> Option<IsoFlags> {
    let cache = ISO.lock();
    cache.iso.iter().find(|e| e.gsi == gsi).map(|e| e.flags)
}

pub(super) fn locate(gsi: u32) -> Option<(IoApicChip, u32)> {
    let chips = IOAPICS.lock();
    for chip in chips.iter().flatten() {
        let end = chip.gsi_base + chip.redirs;
        if gsi >= chip.gsi_base && gsi < end {
            return Some((*chip, gsi - chip.gsi_base));
        }
    }
    None
}
