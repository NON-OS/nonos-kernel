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

pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;
pub const PCI_MAX_BUS: u8 = 255;
pub const PCI_MAX_DEVICE: u8 = 31;
pub const PCI_MAX_FUNCTION: u8 = 7;
pub const PCI_CONFIG_SPACE_SIZE: u16 = 256;
pub const PCIE_CONFIG_SPACE_SIZE: u16 = 4096;
pub const CFG_VENDOR_ID: u16 = 0x00;
pub const CFG_DEVICE_ID: u16 = 0x02;
pub const CFG_COMMAND: u16 = 0x04;
pub const CFG_STATUS: u16 = 0x06;
pub const CFG_REVISION_ID: u16 = 0x08;
pub const CFG_PROG_IF: u16 = 0x09;
pub const CFG_SUBCLASS: u16 = 0x0A;
pub const CFG_CLASS_CODE: u16 = 0x0B;
pub const CFG_CACHE_LINE_SIZE: u16 = 0x0C;
pub const CFG_LATENCY_TIMER: u16 = 0x0D;
pub const CFG_HEADER_TYPE: u16 = 0x0E;
pub const CFG_BIST: u16 = 0x0F;
pub const CFG_BAR0: u16 = 0x10;
pub const CFG_BAR1: u16 = 0x14;
pub const CFG_BAR2: u16 = 0x18;
pub const CFG_BAR3: u16 = 0x1C;
pub const CFG_BAR4: u16 = 0x20;
pub const CFG_BAR5: u16 = 0x24;
pub const CFG_CARDBUS_CIS: u16 = 0x28;
pub const CFG_SUBSYSTEM_VENDOR_ID: u16 = 0x2C;
pub const CFG_SUBSYSTEM_ID: u16 = 0x2E;
pub const CFG_EXPANSION_ROM_BASE: u16 = 0x30;
pub const CFG_CAPABILITIES_PTR: u16 = 0x34;
pub const CFG_INTERRUPT_LINE: u16 = 0x3C;
pub const CFG_INTERRUPT_PIN: u16 = 0x3D;
pub const CFG_MIN_GRANT: u16 = 0x3E;
pub const CFG_MAX_LATENCY: u16 = 0x3F;
pub const CFG_PRIMARY_BUS: u16 = 0x18;
pub const CFG_SECONDARY_BUS: u16 = 0x19;
pub const CFG_SUBORDINATE_BUS: u16 = 0x1A;
pub const CFG_SECONDARY_LATENCY: u16 = 0x1B;
pub const CFG_IO_BASE: u16 = 0x1C;
pub const CFG_IO_LIMIT: u16 = 0x1D;
pub const CFG_SECONDARY_STATUS: u16 = 0x1E;
pub const CFG_MEMORY_BASE: u16 = 0x20;
pub const CFG_MEMORY_LIMIT: u16 = 0x22;
pub const CFG_PREFETCH_MEMORY_BASE: u16 = 0x24;
pub const CFG_PREFETCH_MEMORY_LIMIT: u16 = 0x26;
pub const CFG_PREFETCH_BASE_UPPER: u16 = 0x28;
pub const CFG_PREFETCH_LIMIT_UPPER: u16 = 0x2C;
pub const CFG_IO_BASE_UPPER: u16 = 0x30;
pub const CFG_IO_LIMIT_UPPER: u16 = 0x32;
pub const CFG_BRIDGE_CONTROL: u16 = 0x3E;
pub const CMD_IO_SPACE: u16 = 1 << 0;
pub const CMD_MEMORY_SPACE: u16 = 1 << 1;
pub const CMD_BUS_MASTER: u16 = 1 << 2;
pub const CMD_SPECIAL_CYCLES: u16 = 1 << 3;
pub const CMD_MWI_ENABLE: u16 = 1 << 4;
pub const CMD_VGA_PALETTE_SNOOP: u16 = 1 << 5;
pub const CMD_PARITY_ERROR_RESPONSE: u16 = 1 << 6;
pub const CMD_SERR_ENABLE: u16 = 1 << 8;
pub const CMD_FAST_B2B_ENABLE: u16 = 1 << 9;
pub const CMD_INTERRUPT_DISABLE: u16 = 1 << 10;
pub const STS_INTERRUPT_STATUS: u16 = 1 << 3;
pub const STS_CAPABILITIES_LIST: u16 = 1 << 4;
pub const STS_66MHZ_CAPABLE: u16 = 1 << 5;
pub const STS_FAST_B2B_CAPABLE: u16 = 1 << 7;
pub const STS_MASTER_DATA_PARITY_ERROR: u16 = 1 << 8;
pub const STS_DEVSEL_TIMING_MASK: u16 = 0x3 << 9;
pub const STS_SIGNALED_TARGET_ABORT: u16 = 1 << 11;
pub const STS_RECEIVED_TARGET_ABORT: u16 = 1 << 12;
pub const STS_RECEIVED_MASTER_ABORT: u16 = 1 << 13;
pub const STS_SIGNALED_SYSTEM_ERROR: u16 = 1 << 14;
pub const STS_DETECTED_PARITY_ERROR: u16 = 1 << 15;
pub const HDR_TYPE_STANDARD: u8 = 0x00;
pub const HDR_TYPE_BRIDGE: u8 = 0x01;
pub const HDR_TYPE_CARDBUS: u8 = 0x02;
pub const HDR_TYPE_MULTIFUNCTION: u8 = 0x80;
pub const BAR_TYPE_MASK: u32 = 0x01;
pub const BAR_TYPE_MEMORY: u32 = 0x00;
pub const BAR_TYPE_IO: u32 = 0x01;
pub const BAR_MEMORY_TYPE_MASK: u32 = 0x06;
pub const BAR_MEMORY_TYPE_32: u32 = 0x00;
pub const BAR_MEMORY_TYPE_64: u32 = 0x04;
pub const BAR_MEMORY_PREFETCHABLE: u32 = 0x08;
pub const BAR_MEMORY_ADDR_MASK: u32 = 0xFFFF_FFF0;
pub const BAR_IO_ADDR_MASK: u32 = 0xFFFF_FFFC;
pub const CAP_ID_PM: u8 = 0x01;
pub const CAP_ID_AGP: u8 = 0x02;
pub const CAP_ID_VPD: u8 = 0x03;
pub const CAP_ID_SLOT_ID: u8 = 0x04;
pub const CAP_ID_MSI: u8 = 0x05;
pub const CAP_ID_CHSWP: u8 = 0x06;
pub const CAP_ID_PCIX: u8 = 0x07;
pub const CAP_ID_HT: u8 = 0x08;
pub const CAP_ID_VNDR: u8 = 0x09;
pub const CAP_ID_DBG: u8 = 0x0A;
pub const CAP_ID_CCRC: u8 = 0x0B;
pub const CAP_ID_SHPC: u8 = 0x0C;
pub const CAP_ID_SSVID: u8 = 0x0D;
pub const CAP_ID_AGP3: u8 = 0x0E;
pub const CAP_ID_SECDEV: u8 = 0x0F;
pub const CAP_ID_PCIE: u8 = 0x10;
pub const CAP_ID_MSIX: u8 = 0x11;
pub const CAP_ID_SATA: u8 = 0x12;
pub const CAP_ID_AF: u8 = 0x13;
pub const CAP_ID_EA: u8 = 0x14;
pub const CAP_ID_FPB: u8 = 0x15;
pub const PCIE_CAP_ID_NULL: u16 = 0x0000;
pub const PCIE_CAP_ID_AER: u16 = 0x0001;
pub const PCIE_CAP_ID_VC: u16 = 0x0002;
pub const PCIE_CAP_ID_DSN: u16 = 0x0003;
pub const PCIE_CAP_ID_PWR: u16 = 0x0004;
pub const PCIE_CAP_ID_RCLD: u16 = 0x0005;
pub const PCIE_CAP_ID_RCILC: u16 = 0x0006;
pub const PCIE_CAP_ID_RCEC: u16 = 0x0007;
pub const PCIE_CAP_ID_MFVC: u16 = 0x0008;
pub const PCIE_CAP_ID_VC9: u16 = 0x0009;
pub const PCIE_CAP_ID_RCRB: u16 = 0x000A;
pub const PCIE_CAP_ID_VNDR: u16 = 0x000B;
pub const PCIE_CAP_ID_CAC: u16 = 0x000C;
pub const PCIE_CAP_ID_ACS: u16 = 0x000D;
pub const PCIE_CAP_ID_ARI: u16 = 0x000E;
pub const PCIE_CAP_ID_ATS: u16 = 0x000F;
pub const PCIE_CAP_ID_SRIOV: u16 = 0x0010;
pub const PCIE_CAP_ID_MRIOV: u16 = 0x0011;
pub const PCIE_CAP_ID_MCAST: u16 = 0x0012;
pub const PCIE_CAP_ID_PRI: u16 = 0x0013;
pub const PCIE_CAP_ID_REBAR: u16 = 0x0015;
pub const PCIE_CAP_ID_DPA: u16 = 0x0016;
pub const PCIE_CAP_ID_TPH: u16 = 0x0017;
pub const PCIE_CAP_ID_LTR: u16 = 0x0018;
pub const PCIE_CAP_ID_SECPCI: u16 = 0x0019;
pub const PCIE_CAP_ID_PMUX: u16 = 0x001A;
pub const PCIE_CAP_ID_PASID: u16 = 0x001B;
pub const PCIE_CAP_ID_LNR: u16 = 0x001C;
pub const PCIE_CAP_ID_DPC: u16 = 0x001D;
pub const PCIE_CAP_ID_L1SS: u16 = 0x001E;
pub const PCIE_CAP_ID_PTM: u16 = 0x001F;
pub const PCIE_CAP_ID_MPCIE: u16 = 0x0020;
pub const PCIE_CAP_ID_FRS: u16 = 0x0021;
pub const PCIE_CAP_ID_RTR: u16 = 0x0022;
pub const PCIE_CAP_ID_DVSEC: u16 = 0x0023;
pub const PCIE_CAP_ID_VF_REBAR: u16 = 0x0024;
pub const PCIE_CAP_ID_DLNK: u16 = 0x0025;
pub const PCIE_CAP_ID_16GT: u16 = 0x0026;
pub const PCIE_CAP_ID_LMR: u16 = 0x0027;
pub const PCIE_CAP_ID_HIER_ID: u16 = 0x0028;
pub const PCIE_CAP_ID_NPEM: u16 = 0x0029;
pub const PCIE_CAP_ID_32GT: u16 = 0x002A;
pub const MSI_CTRL_ENABLE: u16 = 1 << 0;
pub const MSI_CTRL_MMC_MASK: u16 = 0x7 << 1;
pub const MSI_CTRL_MME_MASK: u16 = 0x7 << 4;
pub const MSI_CTRL_64BIT: u16 = 1 << 7;
pub const MSI_CTRL_PVM: u16 = 1 << 8;
pub const MSI_CTRL_EXT_MSG_DATA: u16 = 1 << 9;
pub const MSI_CTRL_EXT_MSG_DATA_CAP: u16 = 1 << 10;
pub const MSIX_CTRL_ENABLE: u16 = 1 << 15;
pub const MSIX_CTRL_FUNCTION_MASK: u16 = 1 << 14;
pub const MSIX_CTRL_TABLE_SIZE_MASK: u16 = 0x07FF;
pub const MSIX_ENTRY_SIZE: u32 = 16;
pub const MSIX_ENTRY_ADDR_LO: u32 = 0;
pub const MSIX_ENTRY_ADDR_HI: u32 = 4;
pub const MSIX_ENTRY_DATA: u32 = 8;
pub const MSIX_ENTRY_VECTOR_CTRL: u32 = 12;
pub const MSIX_ENTRY_MASKED: u32 = 1 << 0;
pub const PM_CAP_VER_MASK: u16 = 0x7;
pub const PM_CAP_PME_CLOCK: u16 = 1 << 3;
pub const PM_CAP_DSI: u16 = 1 << 5;
pub const PM_CAP_AUX_MASK: u16 = 0x7 << 6;
pub const PM_CAP_D1: u16 = 1 << 9;
pub const PM_CAP_D2: u16 = 1 << 10;
pub const PM_CAP_PME_D0: u16 = 1 << 11;
pub const PM_CAP_PME_D1: u16 = 1 << 12;
pub const PM_CAP_PME_D2: u16 = 1 << 13;
pub const PM_CAP_PME_D3_HOT: u16 = 1 << 14;
pub const PM_CAP_PME_D3_COLD: u16 = 1 << 15;
pub const PM_CTRL_STATE_MASK: u16 = 0x3;
pub const PM_CTRL_NO_SOFT_RESET: u16 = 1 << 3;
pub const PM_CTRL_PME_ENABLE: u16 = 1 << 8;
pub const PM_CTRL_DATA_SEL_MASK: u16 = 0xF << 9;
pub const PM_CTRL_DATA_SCALE_MASK: u16 = 0x3 << 13;
pub const PM_CTRL_PME_STATUS: u16 = 1 << 15;
pub const PM_STATE_D0: u16 = 0;
pub const PM_STATE_D1: u16 = 1;
pub const PM_STATE_D2: u16 = 2;
pub const PM_STATE_D3_HOT: u16 = 3;
pub const PCIE_TYPE_ENDPOINT: u8 = 0x0;
pub const PCIE_TYPE_LEGACY_ENDPOINT: u8 = 0x1;
pub const PCIE_TYPE_ROOT_PORT: u8 = 0x4;
pub const PCIE_TYPE_UPSTREAM_PORT: u8 = 0x5;
pub const PCIE_TYPE_DOWNSTREAM_PORT: u8 = 0x6;
pub const PCIE_TYPE_PCIE_TO_PCI_BRIDGE: u8 = 0x7;
pub const PCIE_TYPE_PCI_TO_PCIE_BRIDGE: u8 = 0x8;
pub const PCIE_TYPE_ROOT_COMPLEX_ENDPOINT: u8 = 0x9;
pub const PCIE_TYPE_ROOT_COMPLEX_EVENT_COLLECTOR: u8 = 0xA;
pub const PCIE_LINK_SPEED_2_5GT: u8 = 0x1;
pub const PCIE_LINK_SPEED_5GT: u8 = 0x2;
pub const PCIE_LINK_SPEED_8GT: u8 = 0x3;
pub const PCIE_LINK_SPEED_16GT: u8 = 0x4;
pub const PCIE_LINK_SPEED_32GT: u8 = 0x5;
pub const PCIE_LINK_SPEED_64GT: u8 = 0x6;
pub const PCIE_LINK_WIDTH_X1: u8 = 0x01;
pub const PCIE_LINK_WIDTH_X2: u8 = 0x02;
pub const PCIE_LINK_WIDTH_X4: u8 = 0x04;
pub const PCIE_LINK_WIDTH_X8: u8 = 0x08;
pub const PCIE_LINK_WIDTH_X12: u8 = 0x0C;
pub const PCIE_LINK_WIDTH_X16: u8 = 0x10;
pub const PCIE_LINK_WIDTH_X32: u8 = 0x20;
pub const CLASS_UNCLASSIFIED: u8 = 0x00;
pub const CLASS_MASS_STORAGE: u8 = 0x01;
pub const CLASS_NETWORK: u8 = 0x02;
pub const CLASS_DISPLAY: u8 = 0x03;
pub const CLASS_MULTIMEDIA: u8 = 0x04;
pub const CLASS_MEMORY: u8 = 0x05;
pub const CLASS_BRIDGE: u8 = 0x06;
pub const CLASS_SIMPLE_COMM: u8 = 0x07;
pub const CLASS_BASE_PERIPHERAL: u8 = 0x08;
pub const CLASS_INPUT: u8 = 0x09;
pub const CLASS_DOCKING: u8 = 0x0A;
pub const CLASS_PROCESSOR: u8 = 0x0B;
pub const CLASS_SERIAL_BUS: u8 = 0x0C;
pub const CLASS_WIRELESS: u8 = 0x0D;
pub const CLASS_INTELLIGENT_IO: u8 = 0x0E;
pub const CLASS_SATELLITE_COMM: u8 = 0x0F;
pub const CLASS_ENCRYPTION: u8 = 0x10;
pub const CLASS_SIGNAL_PROCESSING: u8 = 0x11;
pub const CLASS_PROCESSING_ACCELERATOR: u8 = 0x12;
pub const CLASS_NON_ESSENTIAL: u8 = 0x13;
pub const CLASS_COPROCESSOR: u8 = 0x40;
pub const CLASS_UNASSIGNED: u8 = 0xFF;
pub const SUBCLASS_STORAGE_SCSI: u8 = 0x00;
pub const SUBCLASS_STORAGE_IDE: u8 = 0x01;
pub const SUBCLASS_STORAGE_FLOPPY: u8 = 0x02;
pub const SUBCLASS_STORAGE_IPI: u8 = 0x03;
pub const SUBCLASS_STORAGE_RAID: u8 = 0x04;
pub const SUBCLASS_STORAGE_ATA: u8 = 0x05;
pub const SUBCLASS_STORAGE_SATA: u8 = 0x06;
pub const SUBCLASS_STORAGE_SAS: u8 = 0x07;
pub const SUBCLASS_STORAGE_NVM: u8 = 0x08;
pub const SUBCLASS_STORAGE_UFS: u8 = 0x09;
pub const SUBCLASS_STORAGE_OTHER: u8 = 0x80;
pub const SUBCLASS_NETWORK_ETHERNET: u8 = 0x00;
pub const SUBCLASS_NETWORK_TOKEN_RING: u8 = 0x01;
pub const SUBCLASS_NETWORK_FDDI: u8 = 0x02;
pub const SUBCLASS_NETWORK_ATM: u8 = 0x03;
pub const SUBCLASS_NETWORK_ISDN: u8 = 0x04;
pub const SUBCLASS_NETWORK_WORLDFIP: u8 = 0x05;
pub const SUBCLASS_NETWORK_PICMG: u8 = 0x06;
pub const SUBCLASS_NETWORK_INFINIBAND: u8 = 0x07;
pub const SUBCLASS_NETWORK_FABRIC: u8 = 0x08;
pub const SUBCLASS_NETWORK_OTHER: u8 = 0x80;
pub const SUBCLASS_DISPLAY_VGA: u8 = 0x00;
pub const SUBCLASS_DISPLAY_XGA: u8 = 0x01;
pub const SUBCLASS_DISPLAY_3D: u8 = 0x02;
pub const SUBCLASS_DISPLAY_OTHER: u8 = 0x80;
pub const SUBCLASS_SERIAL_FIREWIRE: u8 = 0x00;
pub const SUBCLASS_SERIAL_ACCESS_BUS: u8 = 0x01;
pub const SUBCLASS_SERIAL_SSA: u8 = 0x02;
pub const SUBCLASS_SERIAL_USB: u8 = 0x03;
pub const SUBCLASS_SERIAL_FIBRE: u8 = 0x04;
pub const SUBCLASS_SERIAL_SMBUS: u8 = 0x05;
pub const SUBCLASS_SERIAL_INFINIBAND: u8 = 0x06;
pub const SUBCLASS_SERIAL_IPMI: u8 = 0x07;
pub const SUBCLASS_SERIAL_SERCOS: u8 = 0x08;
pub const SUBCLASS_SERIAL_CANBUS: u8 = 0x09;
pub const SUBCLASS_SERIAL_OTHER: u8 = 0x80;
pub const PROGIF_OHCI: u8 = 0x10;
pub const PROGIF_EHCI: u8 = 0x20;
pub const PROGIF_XHCI: u8 = 0x30;
pub const PROGIF_UHCI: u8 = 0x00;
pub const PROGIF_USB4: u8 = 0x40;
pub const PROGIF_DEVICE: u8 = 0xFE;
pub const PROGIF_NVME: u8 = 0x02;
pub const PROGIF_NVME_ADMIN: u8 = 0x03;
pub const PROGIF_AHCI: u8 = 0x01;
pub const PROGIF_AHCI_RAID: u8 = 0x04;
pub const MAX_BAR_SIZE: u64 = 256 * 1024 * 1024 * 1024;
pub const MIN_MMIO_ADDRESS: u64 = 0x100000;
pub const MAX_PHYSICAL_ADDRESS: u64 = 0x0000_FFFF_FFFF_FFFF;
pub const MSI_ADDRESS_BASE: u32 = 0xFEE0_0000;
pub const MSI_ADDRESS_DEST_ID_SHIFT: u32 = 12;
pub const MSI_DATA_VECTOR_MASK: u32 = 0xFF;
pub const MSI_DATA_DELIVERY_FIXED: u32 = 0x000;
pub const MSI_DATA_DELIVERY_LOWEST: u32 = 0x100;
pub const MSI_DATA_TRIGGER_EDGE: u32 = 0x000;
pub const MSI_DATA_TRIGGER_LEVEL: u32 = 0x8000;
pub const MSI_DATA_LEVEL_ASSERT: u32 = 0x4000;
pub const MSI_DATA_LEVEL_DEASSERT: u32 = 0x0000;
pub const BRIDGE_CTL_PARITY_ERROR_RESPONSE: u16 = 1 << 0;
pub const BRIDGE_CTL_SERR_ENABLE: u16 = 1 << 1;
pub const BRIDGE_CTL_ISA_ENABLE: u16 = 1 << 2;
pub const BRIDGE_CTL_VGA_ENABLE: u16 = 1 << 3;
pub const BRIDGE_CTL_VGA_16BIT: u16 = 1 << 4;
pub const BRIDGE_CTL_MASTER_ABORT_MODE: u16 = 1 << 5;
pub const BRIDGE_CTL_SECONDARY_BUS_RESET: u16 = 1 << 6;
pub const BRIDGE_CTL_FAST_B2B_ENABLE: u16 = 1 << 7;
pub const BRIDGE_CTL_PRIMARY_DISCARD_TIMER: u16 = 1 << 8;
pub const BRIDGE_CTL_SECONDARY_DISCARD_TIMER: u16 = 1 << 9;
pub const BRIDGE_CTL_DISCARD_TIMER_STATUS: u16 = 1 << 10;
pub const BRIDGE_CTL_DISCARD_TIMER_SERR_ENABLE: u16 = 1 << 11;
pub const VENDOR_INTEL: u16 = 0x8086;
pub const VENDOR_AMD: u16 = 0x1022;
pub const VENDOR_NVIDIA: u16 = 0x10DE;
pub const VENDOR_QEMU: u16 = 0x1234;
pub const VENDOR_VIRTIO: u16 = 0x1AF4;
pub const VENDOR_REALTEK: u16 = 0x10EC;
pub const VENDOR_BROADCOM: u16 = 0x14E4;
pub const VENDOR_RED_HAT: u16 = 0x1B36;
#[inline]
pub const fn pci_config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

#[inline]
pub const fn bar_offset(index: u8) -> u16 {
    CFG_BAR0 + (index as u16 * 4)
}

pub fn class_name(class: u8) -> &'static str {
    match class {
        CLASS_UNCLASSIFIED => "Unclassified",
        CLASS_MASS_STORAGE => "Mass Storage",
        CLASS_NETWORK => "Network",
        CLASS_DISPLAY => "Display",
        CLASS_MULTIMEDIA => "Multimedia",
        CLASS_MEMORY => "Memory",
        CLASS_BRIDGE => "Bridge",
        CLASS_SIMPLE_COMM => "Simple Communication",
        CLASS_BASE_PERIPHERAL => "Base Peripheral",
        CLASS_INPUT => "Input",
        CLASS_DOCKING => "Docking Station",
        CLASS_PROCESSOR => "Processor",
        CLASS_SERIAL_BUS => "Serial Bus",
        CLASS_WIRELESS => "Wireless",
        CLASS_INTELLIGENT_IO => "Intelligent I/O",
        CLASS_SATELLITE_COMM => "Satellite Communication",
        CLASS_ENCRYPTION => "Encryption",
        CLASS_SIGNAL_PROCESSING => "Signal Processing",
        CLASS_PROCESSING_ACCELERATOR => "Processing Accelerator",
        CLASS_NON_ESSENTIAL => "Non-Essential",
        CLASS_COPROCESSOR => "Coprocessor",
        _ => "Unknown",
    }
}

pub fn capability_name(id: u8) -> &'static str {
    match id {
        CAP_ID_PM => "Power Management",
        CAP_ID_AGP => "AGP",
        CAP_ID_VPD => "Vital Product Data",
        CAP_ID_SLOT_ID => "Slot ID",
        CAP_ID_MSI => "MSI",
        CAP_ID_CHSWP => "CompactPCI Hot Swap",
        CAP_ID_PCIX => "PCI-X",
        CAP_ID_HT => "HyperTransport",
        CAP_ID_VNDR => "Vendor Specific",
        CAP_ID_DBG => "Debug Port",
        CAP_ID_CCRC => "CompactPCI CRC",
        CAP_ID_SHPC => "Hot Plug",
        CAP_ID_SSVID => "Subsystem Vendor ID",
        CAP_ID_AGP3 => "AGP 3.0",
        CAP_ID_SECDEV => "Secure Device",
        CAP_ID_PCIE => "PCI Express",
        CAP_ID_MSIX => "MSI-X",
        CAP_ID_SATA => "SATA",
        CAP_ID_AF => "Advanced Features",
        CAP_ID_EA => "Enhanced Allocation",
        CAP_ID_FPB => "Flattening Portal Bridge",
        _ => "Unknown",
    }
}

pub fn pcie_link_speed_str(speed: u8) -> &'static str {
    match speed {
        PCIE_LINK_SPEED_2_5GT => "2.5 GT/s (Gen1)",
        PCIE_LINK_SPEED_5GT => "5 GT/s (Gen2)",
        PCIE_LINK_SPEED_8GT => "8 GT/s (Gen3)",
        PCIE_LINK_SPEED_16GT => "16 GT/s (Gen4)",
        PCIE_LINK_SPEED_32GT => "32 GT/s (Gen5)",
        PCIE_LINK_SPEED_64GT => "64 GT/s (Gen6)",
        _ => "Unknown",
    }
}
