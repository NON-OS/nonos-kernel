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

use super::super::error::BarType;
use super::super::types::PciBar;
use super::decode::decode_all_bars;
use super::validation::{validate_io_port, validate_mmio_address};

pub fn bar_type(bar: &PciBar) -> BarType {
    match bar {
        PciBar::Memory32 { .. } => BarType::Memory32,
        PciBar::Memory64 { .. } => BarType::Memory64,
        PciBar::Memory { is_64bit: true, .. } => BarType::Memory64,
        PciBar::Memory { is_64bit: false, .. } => BarType::Memory32,
        PciBar::Io { .. } => BarType::Io,
        PciBar::NotPresent => BarType::NotPresent,
    }
}

pub struct BarInfo {
    pub bar: PciBar,
    pub index: u8,
    pub consumes_two_slots: bool,
}

impl BarInfo {
    pub fn from_bar(bar: PciBar, index: u8) -> Self {
        Self {
            consumes_two_slots: bar.is_64bit(),
            bar,
            index,
        }
    }

    pub fn next_index(&self) -> u8 {
        if self.consumes_two_slots {
            self.index + 2
        } else {
            self.index + 1
        }
    }
}

pub fn enumerate_bars(bus: u8, device: u8, function: u8) -> impl Iterator<Item = BarInfo> {
    let bars = decode_all_bars(bus, device, function);

    BarIterator {
        bars,
        current_index: 0,
    }
}

struct BarIterator {
    bars: [PciBar; 6],
    current_index: u8,
}

impl Iterator for BarIterator {
    type Item = BarInfo;

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_index < 6 {
            let index = self.current_index;
            let bar = self.bars[index as usize];

            if bar.is_present() {
                let info = BarInfo::from_bar(bar, index);
                self.current_index = info.next_index();
                return Some(info);
            }

            self.current_index += 1;
        }

        None
    }
}

pub fn calculate_bar_alignment(size: u64) -> u64 {
    if size == 0 {
        return 0;
    }

    let mut alignment = 1u64;
    while alignment < size {
        alignment <<= 1;
    }
    alignment
}

pub fn is_bar_address_valid(bar: &PciBar) -> bool {
    match bar {
        PciBar::Memory32 { address, size, .. } => {
            validate_mmio_address(address.as_u64(), *size).is_ok()
        }
        PciBar::Memory64 { address, size, .. } => {
            validate_mmio_address(address.as_u64(), *size).is_ok()
        }
        PciBar::Memory { address, size, .. } => {
            validate_mmio_address(address.as_u64(), *size as u64).is_ok()
        }
        PciBar::Io { port, size } => validate_io_port(*port, *size).is_ok(),
        PciBar::NotPresent => true,
    }
}
