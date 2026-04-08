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

use alloc::format;
use super::state::{is_initialized, is_disabled};
use super::mask::get_masks;
use super::ops_isr::{read_irr, read_isr};

pub fn dump(mut log: impl FnMut(&str)) {
    let (irr1, irr2) = read_irr();
    let (isr1, isr2) = read_isr();
    let (m1, m2) = get_masks();
    log(&format!("[PIC] Status: init={} disabled={}", is_initialized(), is_disabled()));
    log(&format!("[PIC] Masks: master={:#010b} slave={:#010b}", m1, m2));
    log(&format!("[PIC] IRR:   master={:#010b} slave={:#010b}", irr1, irr2));
    log(&format!("[PIC] ISR:   master={:#010b} slave={:#010b}", isr1, isr2));
}

#[derive(Debug, Clone, Copy)]
pub struct PicStatus {
    pub initialized: bool,
    pub disabled: bool,
    pub master_mask: u8,
    pub slave_mask: u8,
    pub master_irr: u8,
    pub slave_irr: u8,
    pub master_isr: u8,
    pub slave_isr: u8,
}

pub fn status() -> PicStatus {
    let (irr1, irr2) = read_irr();
    let (isr1, isr2) = read_isr();
    let (m1, m2) = get_masks();
    PicStatus {
        initialized: is_initialized(),
        disabled: is_disabled(),
        master_mask: m1,
        slave_mask: m2,
        master_irr: irr1,
        slave_irr: irr2,
        master_isr: isr1,
        slave_isr: isr2,
    }
}
