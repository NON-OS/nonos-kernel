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

extern crate alloc;

use alloc::vec::Vec;

use super::super::config::read32_unchecked;
use super::super::constants::*;
use super::super::types::{PciCapability, PcieCapability};

pub(super) const MAX_CAPABILITY_CHAIN: usize = 64;

pub fn enumerate_capabilities(bus: u8, device: u8, function: u8) -> Vec<PciCapability> {
    let mut caps = Vec::new();

    let status = (read32_unchecked(bus, device, function, CFG_STATUS as u8) >> 16) as u16;
    if (status & STS_CAPABILITIES_LIST) == 0 {
        return caps;
    }

    let mut ptr =
        (read32_unchecked(bus, device, function, CFG_CAPABILITIES_PTR as u8) & 0xFF) as u8;

    let mut guard = 0;
    while ptr >= 0x40 && ptr != 0xFF && guard < MAX_CAPABILITY_CHAIN {
        let header = read32_unchecked(bus, device, function, ptr);
        let id = (header & 0xFF) as u8;
        let next = ((header >> 8) & 0xFF) as u8;

        let version = match id {
            CAP_ID_PM => ((header >> 16) & 0x07) as u8,
            CAP_ID_PCIE => ((header >> 16) & 0x0F) as u8,
            _ => 0,
        };

        caps.push(PciCapability::with_version(id, ptr, version));

        if next == 0 || next == ptr {
            break;
        }
        ptr = next;
        guard += 1;
    }

    caps
}

pub fn enumerate_pcie_capabilities(bus: u8, device: u8, function: u8) -> Vec<PcieCapability> {
    let mut caps = Vec::new();

    let pcie_cap = enumerate_capabilities(bus, device, function)
        .into_iter()
        .find(|c| c.id == CAP_ID_PCIE);

    if pcie_cap.is_none() {
        return caps;
    }

    let mut offset = 0x100u16;
    let mut guard = 0;

    while offset != 0 && offset < PCIE_CONFIG_SPACE_SIZE && guard < MAX_CAPABILITY_CHAIN {
        let header = read_pcie_config(bus, device, function, offset);

        if header == 0 || header == 0xFFFF_FFFF {
            break;
        }

        let id = (header & 0xFFFF) as u16;
        let version = ((header >> 16) & 0x0F) as u8;
        let next = ((header >> 20) & 0xFFF) as u16;

        if id != 0 {
            caps.push(PcieCapability::new(id, version, offset));
        }

        if next == 0 || next == offset {
            break;
        }
        offset = next;
        guard += 1;
    }

    caps
}

pub(super) fn read_pcie_config(bus: u8, device: u8, function: u8, offset: u16) -> u32 {
    if offset >= PCIE_CONFIG_SPACE_SIZE {
        return 0xFFFF_FFFF;
    }

    if offset < PCI_CONFIG_SPACE_SIZE {
        return read32_unchecked(bus, device, function, offset as u8);
    }

    0xFFFF_FFFF
}

pub fn find_capability(bus: u8, device: u8, function: u8, id: u8) -> Option<PciCapability> {
    enumerate_capabilities(bus, device, function)
        .into_iter()
        .find(|c| c.id == id)
}

pub fn has_capability(bus: u8, device: u8, function: u8, id: u8) -> bool {
    find_capability(bus, device, function, id).is_some()
}
