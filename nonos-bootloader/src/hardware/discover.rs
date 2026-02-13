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
use uefi::cstr16;
use uefi::prelude::*;

use crate::log::logger::{log_info, log_warn};

use super::acpi::{discover_acpi_rsdp, get_cpu_count_from_acpi};
use super::cpu::detect_cpu_features;
use super::devices::{enumerate_graphics, enumerate_network, enumerate_pci, enumerate_storage};
use super::display::display_hardware_summary;
use super::memory::discover_memory_size;
use super::types::HardwareInfo;

pub fn discover_system_hardware(system_table: &mut SystemTable<Boot>) -> HardwareInfo {
    let mut hardware = HardwareInfo::default();

    let _ = system_table
        .stdout()
        .output_string(cstr16!("=== HW Discovery ===\r\n"));

    hardware.rsdp_address = discover_acpi_rsdp(system_table);
    hardware.acpi_available = hardware.rsdp_address.is_some();
    if hardware.acpi_available {
        log_info("acpi", "ACPI RSDP found");
    } else {
        log_warn("acpi", "ACPI RSDP not found");
    }

    hardware.memory_size = discover_memory_size(system_table);
    log_info(
        "memory",
        &format!("Total RAM: {} MiB", hardware.memory_size / (1024 * 1024)),
    );

    hardware.cpu_count = if let Some(rsdp) = hardware.rsdp_address {
        get_cpu_count_from_acpi(rsdp)
    } else {
        1
    };

    hardware.storage_devices = enumerate_storage(system_table);
    hardware.network_interfaces = enumerate_network(system_table);
    hardware.graphics_devices = enumerate_graphics(system_table);
    hardware.pci_devices = enumerate_pci(system_table);

    let cpu_flags = detect_cpu_features();
    log_info(
        "cpu",
        &format!(
            "CPU features: NXE={} SMEP={} SMAP={} UMIP={}",
            cpu_flags.nxe, cpu_flags.smep, cpu_flags.smap, cpu_flags.umip
        ),
    );

    display_hardware_summary(&hardware, system_table);

    hardware
}
