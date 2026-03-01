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
use super::config;
use super::error::Result;
use super::security::{get_security_stats, set_allowlist, add_to_blocklist, remove_from_blocklist, clear_blocklist};

pub fn pci_read_config32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    config::read32_unchecked(bus, device, function, offset)
}

pub fn pci_write_config32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    config::write32_unchecked(bus, device, function, offset, value)
}

pub fn pci_read_config32_safe(
    bus: u8,
    device: u8,
    function: u8,
    offset: u8,
) -> Result<u32> {
    config::read32(bus, device, function, offset as u16)
}

pub fn pci_write_config32_safe(
    bus: u8,
    device: u8,
    function: u8,
    offset: u8,
    value: u32,
) -> Result<()> {
    config::write32(bus, device, function, offset as u16, value)
}

pub fn get_pci_stats_tuple() -> (u64, u64, u64) {
    let security = get_security_stats();
    let (reads, writes) = config::get_config_stats();
    (reads, writes, security.violations)
}

pub fn set_device_allowlist(list: Option<Vec<(u16, u16)>>) {
    set_allowlist(list);
}

pub fn add_device_to_blocklist(vendor_id: u16, device_id: u16) {
    add_to_blocklist(vendor_id, device_id);
}

pub fn remove_device_from_blocklist(vendor_id: u16, device_id: u16) {
    remove_from_blocklist(vendor_id, device_id);
}

pub fn clear_device_blocklist() {
    clear_blocklist();
}
