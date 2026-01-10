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

use super::*;

#[test]
fn test_pci_address_creation() {
    let addr = types::PciAddress::new(0, 1, 2);
    assert_eq!(addr.bus, 0);
    assert_eq!(addr.device, 1);
    assert_eq!(addr.function, 2);
}

#[test]
fn test_pci_address_bdf_conversion() {
    let addr = types::PciAddress::new(5, 10, 3);
    let bdf = addr.to_bdf();
    let restored = types::PciAddress::from_bdf(bdf);

    assert_eq!(restored.bus, addr.bus);
    assert_eq!(restored.device, addr.device);
    assert_eq!(restored.function, addr.function);
}

#[test]
fn test_pci_address_display() {
    let addr = types::PciAddress::new(0x12, 0x0A, 0x03);
    let display = alloc::format!("{}", addr);
    assert_eq!(display, "12:0a.3");
}

#[test]
fn test_config_address_calculation() {
    let addr = constants::pci_config_address(0, 0, 0, 0);
    assert_eq!(addr & (1 << 31), 1 << 31);

    let addr = constants::pci_config_address(5, 10, 3, 0x10);
    let expected = (1u32 << 31) | (5u32 << 16) | (10u32 << 11) | (3u32 << 8) | 0x10;
    assert_eq!(addr, expected);
}

#[test]
fn test_bar_offset_calculation() {
    assert_eq!(constants::bar_offset(0), constants::CFG_BAR0);
    assert_eq!(constants::bar_offset(1), constants::CFG_BAR1);
    assert_eq!(constants::bar_offset(5), constants::CFG_BAR5);
}

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
fn test_pci_bar_properties() {
    let mem32 = types::PciBar::Memory32 {
        address: x86_64::PhysAddr::new(0xF000_0000),
        size: 0x1000,
        prefetchable: true,
    };

    assert!(mem32.is_memory());
    assert!(!mem32.is_io());
    assert!(!mem32.is_64bit());
    assert!(mem32.is_prefetchable());
    assert!(mem32.is_present());
    assert_eq!(mem32.size(), 0x1000);
    assert_eq!(mem32.address(), Some(x86_64::PhysAddr::new(0xF000_0000)));

    let mem64 = types::PciBar::Memory64 {
        address: x86_64::PhysAddr::new(0x1_0000_0000),
        size: 0x100000,
        prefetchable: false,
    };

    assert!(mem64.is_64bit());
    assert!(!mem64.is_prefetchable());

    let io = types::PciBar::Io { port: 0x1000, size: 0x100 };
    assert!(io.is_io());
    assert!(!io.is_memory());
    assert_eq!(io.port(), Some(0x1000));

    let none = types::PciBar::NotPresent;
    assert!(!none.is_present());
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
fn test_class_name_lookup() {
    assert_eq!(constants::class_name(constants::CLASS_MASS_STORAGE), "Mass Storage");
    assert_eq!(constants::class_name(constants::CLASS_NETWORK), "Network");
    assert_eq!(constants::class_name(constants::CLASS_DISPLAY), "Display");
    assert_eq!(constants::class_name(constants::CLASS_SERIAL_BUS), "Serial Bus");
}

#[test]
fn test_capability_name_lookup() {
    assert_eq!(constants::capability_name(constants::CAP_ID_MSI), "MSI");
    assert_eq!(constants::capability_name(constants::CAP_ID_MSIX), "MSI-X");
    assert_eq!(constants::capability_name(constants::CAP_ID_PM), "Power Management");
    assert_eq!(constants::capability_name(constants::CAP_ID_PCIE), "PCI Express");
}

#[test]
fn test_pcie_link_speed_string() {
    assert_eq!(constants::pcie_link_speed_str(constants::PCIE_LINK_SPEED_2_5GT), "2.5 GT/s (Gen1)");
    assert_eq!(constants::pcie_link_speed_str(constants::PCIE_LINK_SPEED_8GT), "8 GT/s (Gen3)");
    assert_eq!(constants::pcie_link_speed_str(constants::PCIE_LINK_SPEED_32GT), "32 GT/s (Gen5)");
}

#[test]
fn test_error_display() {
    let err = error::PciError::InvalidDevice(32);
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("32"));

    let err = error::PciError::DeviceBlocked { vendor: 0x1234, device: 0x5678 };
    let msg = alloc::format!("{}", err);
    assert!(msg.contains("1234"));
    assert!(msg.contains("5678"));
}

#[test]
fn test_error_classification() {
    assert!(error::PciError::RootComplexError.is_fatal());
    assert!(!error::PciError::DeviceNotFound.is_fatal());

    assert!(error::PciError::DeviceBlocked { vendor: 0, device: 0 }.is_security_related());
    assert!(!error::PciError::DeviceNotFound.is_security_related());

    assert!(error::PciError::DeviceNotFound.is_recoverable());
    assert!(!error::PciError::RootComplexError.is_recoverable());
}

#[test]
fn test_security_level_ordering() {
    assert!(security::SecurityLevel::Critical > security::SecurityLevel::High);
    assert!(security::SecurityLevel::High > security::SecurityLevel::Medium);
    assert!(security::SecurityLevel::Medium > security::SecurityLevel::Low);
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
fn test_stats_snapshot() {
    let stats = stats::PciStats::snapshot();
    assert!(stats.total_devices < 1000);
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
fn test_bar_alignment_calculation() {
    assert_eq!(bar::calculate_bar_alignment(0), 0);
    assert_eq!(bar::calculate_bar_alignment(1), 1);
    assert_eq!(bar::calculate_bar_alignment(100), 128);
    assert_eq!(bar::calculate_bar_alignment(256), 256);
    assert_eq!(bar::calculate_bar_alignment(1000), 1024);
}

#[test]
fn test_bar_type_identification() {
    let mem32 = types::PciBar::Memory32 {
        address: x86_64::PhysAddr::new(0xF000_0000),
        size: 0x1000,
        prefetchable: false,
    };
    assert_eq!(bar::bar_type(&mem32), error::BarType::Memory32);

    let mem64 = types::PciBar::Memory64 {
        address: x86_64::PhysAddr::new(0x1_0000_0000),
        size: 0x1000,
        prefetchable: false,
    };
    assert_eq!(bar::bar_type(&mem64), error::BarType::Memory64);

    let io = types::PciBar::Io { port: 0x1000, size: 0x100 };
    assert_eq!(bar::bar_type(&io), error::BarType::Io);

    let none = types::PciBar::NotPresent;
    assert_eq!(bar::bar_type(&none), error::BarType::NotPresent);
}

#[test]
fn test_command_register_bits() {
    assert_eq!(constants::CMD_IO_SPACE, 1 << 0);
    assert_eq!(constants::CMD_MEMORY_SPACE, 1 << 1);
    assert_eq!(constants::CMD_BUS_MASTER, 1 << 2);
    assert_eq!(constants::CMD_INTERRUPT_DISABLE, 1 << 10);
}

#[test]
fn test_status_register_bits() {
    assert_eq!(constants::STS_CAPABILITIES_LIST, 1 << 4);
    assert_eq!(constants::STS_66MHZ_CAPABLE, 1 << 5);
    assert_eq!(constants::STS_DETECTED_PARITY_ERROR, 1 << 15);
}

#[test]
fn test_vendor_ids() {
    assert_eq!(constants::VENDOR_INTEL, 0x8086);
    assert_eq!(constants::VENDOR_AMD, 0x1022);
    assert_eq!(constants::VENDOR_NVIDIA, 0x10DE);
    assert_eq!(constants::VENDOR_VIRTIO, 0x1AF4);
}
