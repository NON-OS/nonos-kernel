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

#[test]
fn test_class_code_methods() {
    let storage = types::ClassCode::new(constants::CLASS_MASS_STORAGE, constants::SUBCLASS_STORAGE_NVM, 0x02);
    assert!(storage.is_storage());
    assert!(storage.is_nvme());
    assert!(!storage.is_network());

    let network = types::ClassCode::new(constants::CLASS_NETWORK, 0x00, 0x00);
    assert!(network.is_network());
    assert!(!network.is_storage());

    let usb = types::ClassCode::new(constants::CLASS_SERIAL_BUS, constants::SUBCLASS_SERIAL_USB, 0x30);
    assert!(usb.is_usb());

    let ahci = types::ClassCode::new(constants::CLASS_MASS_STORAGE, constants::SUBCLASS_STORAGE_SATA, constants::PROGIF_AHCI);
    assert!(ahci.is_ahci());
}

#[test]
fn test_header_type_parsing() {
    assert_eq!(types::HeaderType::from(0x00), types::HeaderType::Standard);
    assert_eq!(types::HeaderType::from(0x01), types::HeaderType::PciToPciBridge);
    assert_eq!(types::HeaderType::from(0x02), types::HeaderType::CardBusBridge);
    assert_eq!(types::HeaderType::from(0x80), types::HeaderType::Standard);
    assert!(types::HeaderType::is_multifunction(0x80));
    assert!(!types::HeaderType::is_multifunction(0x00));
}

#[test]
fn test_capability_creation() {
    let cap = types::PciCapability::new(constants::CAP_ID_MSI, 0x50);
    assert_eq!(cap.id, constants::CAP_ID_MSI);
    assert_eq!(cap.offset, 0x50);
    assert_eq!(cap.name(), "MSI");

    let cap_ver = types::PciCapability::with_version(constants::CAP_ID_PCIE, 0x60, 2);
    assert_eq!(cap_ver.version, 2);
}

#[test]
fn test_msi_message_creation() {
    let msg = types::MsiMessage::for_local_apic(0x30);
    assert_eq!(msg.address & 0xFFF0_0000, constants::MSI_ADDRESS_BASE as u64);
    assert_eq!(msg.data & 0xFF, 0x30);
}

#[test]
fn test_device_id_matching() {
    let id = types::DeviceId::new(0x8086, 0x1234);
    assert!(id.matches(0x8086, 0x1234));
    assert!(!id.matches(0x8086, 0x5678));
    assert!(!id.matches(0x1022, 0x1234));
}

#[test]
fn test_pcie_device_type_parsing() {
    assert_eq!(
        types::PcieDeviceType::from(constants::PCIE_TYPE_ENDPOINT),
        types::PcieDeviceType::Endpoint
    );
    assert_eq!(
        types::PcieDeviceType::from(constants::PCIE_TYPE_ROOT_PORT),
        types::PcieDeviceType::RootPort
    );
    assert_eq!(
        types::PcieDeviceType::from(0xFF),
        types::PcieDeviceType::Unknown(0xFF)
    );
}

#[test]
fn test_pci_device_creation() {
    let addr = types::PciAddress::new(0, 1, 0);
    let dev = types::PciDevice::new(addr);

    assert_eq!(dev.bus(), 0);
    assert_eq!(dev.device(), 1);
    assert_eq!(dev.function(), 0);
    assert_eq!(dev.vendor_id(), 0xFFFF);
    assert!(!dev.supports_msi());
    assert!(!dev.supports_msix());
    assert!(!dev.is_pcie());
}

#[test]
fn test_bridge_info_creation() {
    let info = types::BridgeInfo::new();
    assert_eq!(info.primary_bus, 0);
    assert_eq!(info.secondary_bus, 0);
    assert_eq!(info.subordinate_bus, 0);
    assert_eq!(info.io_window(), (0, 0));
    assert_eq!(info.memory_window(), (0, 0));
}

#[test]
fn test_msi_info_vectors() {
    let msi = types::MsiInfo {
        offset: 0x50,
        is_64bit: true,
        per_vector_mask: true,
        multi_message_capable: 3,
        multi_message_enabled: 2,
        enabled: false,
    };

    assert_eq!(msi.max_vectors(), 8);
    assert_eq!(msi.allocated_vectors(), 4);
}

#[test]
fn test_msix_info_vectors() {
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

    assert_eq!(msix.vector_count(), 16);
}

#[test]
fn test_power_management_info() {
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

    assert!(pm.supports_d1());
    assert!(pm.supports_d2());
    assert!(pm.supports_pme_from_d0());
    assert!(pm.supports_pme_from_d3_hot());
    assert!(pm.supports_pme_from_d3_cold());
    assert_eq!(pm.state_name(), "D0");
}

#[test]
fn test_stats_snapshot() {
    let stats = stats::PciStats::snapshot();
    assert!(stats.total_devices < 1000);
}
