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

pub mod error;
pub mod constants;
pub mod types;
pub mod config;
pub mod bar;
pub mod capabilities;
pub mod msi;
pub mod security;
pub mod stats;
pub mod manager;

#[cfg(test)]
mod tests;

pub use error::{PciError, Result};
pub use types::{
    PciAddress, PciBar, PciCapability, PcieCapability, DeviceId, ClassCode,
    HeaderType, MsiInfo, MsixInfo, PowerManagementInfo, PcieInfo, PcieDeviceType,
    PciDevice, BridgeInfo, MsiMessage,
};
pub use config::{ConfigSpace, BridgeConfigSpace, read32_unchecked, write32_unchecked};
pub use bar::{decode_bar, decode_all_bars, decode_all_bars_unchecked, enumerate_bars, BarInfo};
pub use capabilities::{
    enumerate_capabilities, enumerate_pcie_capabilities, find_capability, has_capability,
    get_msi_info, get_msix_info, get_power_management_info, get_pcie_info,
    CapabilityWalker,
};
pub use msi::{
    configure_msi, configure_msi_multi, disable_msi, is_msi_enabled,
    mask_msi_vector, unmask_msi_vector,
    configure_msix, configure_msix_single, enable_msix, disable_msix, is_msix_enabled,
    mask_all_msix, unmask_all_msix, mask_msix_vector, unmask_msix_vector,
    MsiController, disable_legacy_interrupt, enable_legacy_interrupt,
};
pub use security::{
    SecurityPolicy, set_security_policy, get_security_policy,
    validate_config_write, check_device_allowed,
    approve_bus_master, revoke_bus_master, clear_bus_master_approvals,
    add_to_blocklist, remove_from_blocklist, clear_blocklist,
    set_allowlist, add_to_allowlist, clear_allowlist,
    is_dma_capable, is_security_relevant, device_security_level, SecurityLevel,
    get_security_stats, reset_security_stats, SecurityStats,
    audit_device, DeviceAuditInfo, validate_device_for_driver, prepare_device_for_dma,
};
pub use stats::PciStats;
pub use manager::{
    init_pci, get_pci_manager, is_initialized,
    scan_and_collect, scan_and_collect_safe,
    find_device_by_class, find_device_by_id,
    with_manager, get_device_by_address, get_device_by_class,
    count_devices, get_pci_stats,
    PciManager,
};

pub fn pci_read_config32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    read32_unchecked(bus, device, function, offset)
}

pub fn pci_write_config32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    write32_unchecked(bus, device, function, offset, value)
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

pub fn set_device_allowlist(list: Option<alloc::vec::Vec<(u16, u16)>>) {
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

pub use crate::arch::x86_64::pci::PciStats as LegacyPciStats;
