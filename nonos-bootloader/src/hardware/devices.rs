// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::format;
use uefi::prelude::*;

use crate::log::logger::log_info;

pub fn enumerate_storage(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let count = bs
        .find_handles::<uefi::proto::media::block::BlockIO>()
        .map(|h| h.len())
        .unwrap_or(0);
    log_info("storage", &format!("Storage devices: {}", count));
    count
}

pub fn enumerate_network(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let count = bs
        .find_handles::<uefi::proto::network::snp::SimpleNetwork>()
        .map(|h| h.len())
        .unwrap_or(0);
    log_info("network", &format!("Network interfaces: {}", count));
    count
}

pub fn enumerate_graphics(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let count = bs
        .find_handles::<uefi::proto::console::gop::GraphicsOutput>()
        .map(|h| h.len())
        .unwrap_or(0);
    log_info("graphics", &format!("Graphics devices: {}", count));
    count
}

///
pub fn enumerate_pci(system_table: &mut SystemTable<Boot>) -> usize {
    let bs = system_table.boot_services();
    let count = bs
        .find_handles::<uefi::proto::device_path::DevicePath>()
        .map(|h| h.len())
        .unwrap_or(0);
    log_info("pci", &format!("PCI devices: {}", count));
    count
}

/*
 * Detect dual GPU / nvidia optimus setups (issue #8)
 *
 * Laptops with intel igpu + nvidia dgpu expose multiple GOP handles.
 * The nvidia UEFI driver has issues during ExitBootServices - it does
 * something weird that causes hangs on certain firmware.
 *
 * If we see >1 GOP handle, assume optimus and enable workarounds.
 * Tested on Acer Nitro, ASUS ROG, MSI Stealth, HP EliteDesk.
 */
pub fn detect_dual_gpu(system_table: &mut SystemTable<Boot>) -> bool {
    let bs = system_table.boot_services();

    let gop_count = bs
        .find_handles::<uefi::proto::console::gop::GraphicsOutput>()
        .map(|h| h.len())
        .unwrap_or(0);

    if gop_count > 1 {
        log_info("gpu", "dual GPU detected (multiple GOP handles)");
        return true;
    }

    false
}

/*
 * Check if this hardware needs safe exit mode
 *
 * Returns true for machines known to have ExitBootServices problems.
 * Currently just checks for dual GPU but can add more checks here
 * if we find other patterns (SMBIOS vendor string, etc).
 */
pub fn needs_safe_exit(system_table: &mut SystemTable<Boot>) -> bool {
    detect_dual_gpu(system_table)
}
