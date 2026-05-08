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

//! CONFIG.MaxSlotsEn — bits 7:0. Tells the controller how many
//! device slots the system intends to use. Larger than HCSPARAMS1
//! is illegal; v1 sets this equal to MaxSlots.

use crate::constants::CONFIG;
use crate::regs::{mmio_read32, mmio_write32};

pub fn config_set_max_slots(op_base: u64, max_slots: u8) {
    let cur = mmio_read32(op_base + CONFIG) & !0xFF;
    mmio_write32(op_base + CONFIG, cur | (max_slots as u32));
}
