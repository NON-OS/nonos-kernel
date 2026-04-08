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

use alloc::vec::Vec;
use super::types::Rte;
use super::state::IOAPICS;
use super::mmio::redtbl_read;
use super::ops_route::program_route;
use super::ops_helpers::locate;

pub fn query(gsi: u32) -> Option<Rte> {
    let (chip, idx) = locate(gsi)?;
    let (low, high) = unsafe { redtbl_read(chip.mmio, idx) };
    Some(Rte::from_u32s(low, high))
}

pub fn snapshot() -> Vec<(u32, Rte)> {
    let mut out = Vec::new();
    let chips = IOAPICS.lock();
    for chip in chips.iter().flatten() {
        for i in 0..chip.redirs {
            let (low, high) = unsafe { redtbl_read(chip.mmio, i) };
            out.push((chip.gsi_base + i, Rte::from_u32s(low, high)));
        }
    }
    out
}

pub fn restore(snap: &[(u32, Rte)]) {
    for (gsi, rte) in snap {
        let _ = program_route(*gsi, Rte { masked: true, ..*rte });
    }
}
