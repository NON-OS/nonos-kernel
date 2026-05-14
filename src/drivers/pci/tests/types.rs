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

use crate::drivers::pci::*;
use crate::test::framework::TestResult;

pub(crate) fn test_class_code_methods() -> TestResult {
    let storage =
        types::ClassCode::new(constants::CLASS_MASS_STORAGE, constants::SUBCLASS_STORAGE_NVM, 0x02);
    if !storage.is_storage() {
        return TestResult::Fail;
    }
    if !storage.is_nvme() {
        return TestResult::Fail;
    }
    if storage.is_network() {
        return TestResult::Fail;
    }

    let network = types::ClassCode::new(constants::CLASS_NETWORK, 0x00, 0x00);
    if !network.is_network() {
        return TestResult::Fail;
    }
    if network.is_storage() {
        return TestResult::Fail;
    }

    let usb =
        types::ClassCode::new(constants::CLASS_SERIAL_BUS, constants::SUBCLASS_SERIAL_USB, 0x30);
    if !usb.is_usb() {
        return TestResult::Fail;
    }

    let ahci = types::ClassCode::new(
        constants::CLASS_MASS_STORAGE,
        constants::SUBCLASS_STORAGE_SATA,
        constants::PROGIF_AHCI,
    );
    if !ahci.is_ahci() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_header_type_parsing() -> TestResult {
    if types::HeaderType::from(0x00) != types::HeaderType::Standard {
        return TestResult::Fail;
    }
    if types::HeaderType::from(0x01) != types::HeaderType::PciToPciBridge {
        return TestResult::Fail;
    }
    if types::HeaderType::from(0x02) != types::HeaderType::CardBusBridge {
        return TestResult::Fail;
    }
    if types::HeaderType::from(0x80) != types::HeaderType::Standard {
        return TestResult::Fail;
    }
    if !types::HeaderType::is_multifunction(0x80) {
        return TestResult::Fail;
    }
    if types::HeaderType::is_multifunction(0x00) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_creation() -> TestResult {
    let cap = types::PciCapability::new(constants::CAP_ID_MSI, 0x50);
    if cap.id != constants::CAP_ID_MSI {
        return TestResult::Fail;
    }
    if cap.offset != 0x50 {
        return TestResult::Fail;
    }
    if cap.name() != "MSI" {
        return TestResult::Fail;
    }

    let cap_ver = types::PciCapability::with_version(constants::CAP_ID_PCIE, 0x60, 2);
    if cap_ver.version != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msi_message_creation() -> TestResult {
    let msg = types::MsiMessage::for_local_apic(0x30, 7);
    if msg.address & 0xFFF0_0000 != constants::MSI_ADDRESS_BASE as u64 {
        return TestResult::Fail;
    }
    if (msg.address >> constants::MSI_ADDRESS_DEST_ID_SHIFT) & 0xFF != 7 {
        return TestResult::Fail;
    }
    if msg.data & 0xFF != 0x30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_matching() -> TestResult {
    let id = types::DeviceId::new(0x8086, 0x1234);
    if !id.matches(0x8086, 0x1234) {
        return TestResult::Fail;
    }
    if id.matches(0x8086, 0x5678) {
        return TestResult::Fail;
    }
    if id.matches(0x1022, 0x1234) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcie_device_type_parsing() -> TestResult {
    if types::PcieDeviceType::from(constants::PCIE_TYPE_ENDPOINT) != types::PcieDeviceType::Endpoint
    {
        return TestResult::Fail;
    }
    if types::PcieDeviceType::from(constants::PCIE_TYPE_ROOT_PORT)
        != types::PcieDeviceType::RootPort
    {
        return TestResult::Fail;
    }
    if types::PcieDeviceType::from(0xFF) != types::PcieDeviceType::Unknown(0xFF) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_device_creation() -> TestResult {
    let addr = types::PciAddress::new(0, 1, 0);
    let dev = types::PciDevice::new(addr);

    if dev.bus() != 0 {
        return TestResult::Fail;
    }
    if dev.device() != 1 {
        return TestResult::Fail;
    }
    if dev.function() != 0 {
        return TestResult::Fail;
    }
    if dev.vendor_id() != 0xFFFF {
        return TestResult::Fail;
    }
    if dev.supports_msi() {
        return TestResult::Fail;
    }
    if dev.supports_msix() {
        return TestResult::Fail;
    }
    if dev.is_pcie() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bridge_info_creation() -> TestResult {
    let info = types::BridgeInfo::new();
    if info.primary_bus != 0 {
        return TestResult::Fail;
    }
    if info.secondary_bus != 0 {
        return TestResult::Fail;
    }
    if info.subordinate_bus != 0 {
        return TestResult::Fail;
    }
    if info.io_window() != (0, 0) {
        return TestResult::Fail;
    }
    if info.memory_window() != (0, 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msi_info_vectors() -> TestResult {
    let msi = types::MsiInfo {
        offset: 0x50,
        is_64bit: true,
        per_vector_mask: true,
        multi_message_capable: 3,
        multi_message_enabled: 2,
        enabled: false,
    };

    if msi.max_vectors() != 8 {
        return TestResult::Fail;
    }
    if msi.allocated_vectors() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msix_info_vectors() -> TestResult {
    let msix = types::MsixInfo {
        offset: 0x70,
        table_size: 15,
        table_bar: 0,
        table_offset: 0x2000,
        pba_bar: 0,
        pba_offset: 0x3000,
        enabled: false,
        function_mask: false,
    };

    if msix.vector_count() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_power_management_info() -> TestResult {
    let pm = types::PowerManagementInfo {
        offset: 0x40,
        version: 3,
        pme_clock: false,
        dsi: false,
        aux_current: 0,
        d1_support: true,
        d2_support: true,
        pme_support: 0b11111,
        current_state: 0,
        no_soft_reset: true,
        pme_enabled: false,
        pme_status: false,
    };

    if !pm.supports_d1() {
        return TestResult::Fail;
    }
    if !pm.supports_d2() {
        return TestResult::Fail;
    }
    if !pm.supports_pme_from_d0() {
        return TestResult::Fail;
    }
    if !pm.supports_pme_from_d3_hot() {
        return TestResult::Fail;
    }
    if !pm.supports_pme_from_d3_cold() {
        return TestResult::Fail;
    }
    if pm.state_name() != "D0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_snapshot() -> TestResult {
    let stats = stats::PciStats::snapshot();
    if !(stats.total_devices < 1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
