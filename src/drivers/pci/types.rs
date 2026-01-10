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

use alloc::vec::Vec;
use core::fmt;
use x86_64::PhysAddr;

use super::constants::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self { bus, device, function }
    }

    pub const fn from_bdf(bdf: u16) -> Self {
        Self {
            bus: ((bdf >> 8) & 0xFF) as u8,
            device: ((bdf >> 3) & 0x1F) as u8,
            function: (bdf & 0x07) as u8,
        }
    }

    pub const fn to_bdf(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.device as u16) << 3) | (self.function as u16)
    }

    pub const fn config_address(&self, offset: u8) -> u32 {
        pci_config_address(self.bus, self.device, self.function, offset)
    }
}

impl fmt::Display for PciAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciBar {
    Memory32 {
        address: PhysAddr,
        size: u64,
        prefetchable: bool,
    },
    Memory64 {
        address: PhysAddr,
        size: u64,
        prefetchable: bool,
    },
    Memory {
        address: PhysAddr,
        size: usize,
        is_prefetchable: bool,
        is_64bit: bool,
    },
    Io {
        port: u16,
        size: u32,
    },
    NotPresent,
}

impl PciBar {
    pub fn address(&self) -> Option<PhysAddr> {
        match self {
            PciBar::Memory32 { address, .. } => Some(*address),
            PciBar::Memory64 { address, .. } => Some(*address),
            PciBar::Memory { address, .. } => Some(*address),
            _ => None,
        }
    }

    pub fn port(&self) -> Option<u16> {
        match self {
            PciBar::Io { port, .. } => Some(*port),
            _ => None,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            PciBar::Memory32 { size, .. } => *size,
            PciBar::Memory64 { size, .. } => *size,
            PciBar::Memory { size, .. } => *size as u64,
            PciBar::Io { size, .. } => *size as u64,
            PciBar::NotPresent => 0,
        }
    }

    pub fn is_memory(&self) -> bool {
        matches!(self, PciBar::Memory32 { .. } | PciBar::Memory64 { .. } | PciBar::Memory { .. })
    }

    pub fn is_io(&self) -> bool {
        matches!(self, PciBar::Io { .. })
    }

    pub fn is_64bit(&self) -> bool {
        match self {
            PciBar::Memory64 { .. } => true,
            PciBar::Memory { is_64bit, .. } => *is_64bit,
            _ => false,
        }
    }

    pub fn is_prefetchable(&self) -> bool {
        match self {
            PciBar::Memory32 { prefetchable, .. } => *prefetchable,
            PciBar::Memory64 { prefetchable, .. } => *prefetchable,
            PciBar::Memory { is_prefetchable, .. } => *is_prefetchable,
            _ => false,
        }
    }

    pub fn is_present(&self) -> bool {
        !matches!(self, PciBar::NotPresent)
    }

    /// Returns the MMIO base address and size for memory BARs.
    /// Returns None for I/O BARs or NotPresent.
    pub fn mmio_region(&self) -> Option<(PhysAddr, usize)> {
        match self {
            PciBar::Memory32 { address, size, .. } => Some((*address, *size as usize)),
            PciBar::Memory64 { address, size, .. } => Some((*address, *size as usize)),
            PciBar::Memory { address, size, .. } => Some((*address, *size)),
            _ => None,
        }
    }

    /// Returns the MMIO virtual address (assumes identity mapping) and size.
    /// Returns None for I/O BARs or NotPresent.
    pub fn mmio_virt(&self) -> Option<(x86_64::VirtAddr, usize)> {
        self.mmio_region()
            .map(|(phys, size)| (x86_64::VirtAddr::new(phys.as_u64()), size))
    }
}

impl Default for PciBar {
    fn default() -> Self {
        PciBar::NotPresent
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciCapability {
    pub id: u8,
    pub offset: u8,
    pub version: u8,
}

impl PciCapability {
    pub const fn new(id: u8, offset: u8) -> Self {
        Self { id, offset, version: 0 }
    }

    pub const fn with_version(id: u8, offset: u8, version: u8) -> Self {
        Self { id, offset, version }
    }

    pub fn name(&self) -> &'static str {
        capability_name(self.id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcieCapability {
    pub id: u16,
    pub version: u8,
    pub offset: u16,
}

impl PcieCapability {
    pub const fn new(id: u16, version: u8, offset: u16) -> Self {
        Self { id, version, offset }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceId {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
    pub revision: u8,
}

impl DeviceId {
    pub const fn new(vendor_id: u16, device_id: u16) -> Self {
        Self {
            vendor_id,
            device_id,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
            revision: 0,
        }
    }

    pub fn matches(&self, vendor: u16, device: u16) -> bool {
        self.vendor_id == vendor && self.device_id == device
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassCode {
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

impl ClassCode {
    pub const fn new(class: u8, subclass: u8, prog_if: u8) -> Self {
        Self { class, subclass, prog_if }
    }

    pub fn name(&self) -> &'static str {
        class_name(self.class)
    }

    pub fn is_bridge(&self) -> bool {
        self.class == CLASS_BRIDGE
    }

    pub fn is_storage(&self) -> bool {
        self.class == CLASS_MASS_STORAGE
    }

    pub fn is_network(&self) -> bool {
        self.class == CLASS_NETWORK
    }

    pub fn is_display(&self) -> bool {
        self.class == CLASS_DISPLAY
    }

    pub fn is_usb(&self) -> bool {
        self.class == CLASS_SERIAL_BUS && self.subclass == SUBCLASS_SERIAL_USB
    }

    pub fn is_nvme(&self) -> bool {
        self.class == CLASS_MASS_STORAGE && self.subclass == SUBCLASS_STORAGE_NVM
    }

    pub fn is_ahci(&self) -> bool {
        self.class == CLASS_MASS_STORAGE && self.subclass == SUBCLASS_STORAGE_SATA
    }
}

impl fmt::Display for ClassCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}.{:02x}.{:02x}", self.class, self.subclass, self.prog_if)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderType {
    Standard,
    PciToPciBridge,
    CardBusBridge,
    Unknown(u8),
}

impl From<u8> for HeaderType {
    fn from(value: u8) -> Self {
        match value & 0x7F {
            HDR_TYPE_STANDARD => HeaderType::Standard,
            HDR_TYPE_BRIDGE => HeaderType::PciToPciBridge,
            HDR_TYPE_CARDBUS => HeaderType::CardBusBridge,
            other => HeaderType::Unknown(other),
        }
    }
}

impl HeaderType {
    pub fn is_multifunction(raw: u8) -> bool {
        (raw & HDR_TYPE_MULTIFUNCTION) != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiInfo {
    pub offset: u8,
    pub is_64bit: bool,
    pub per_vector_mask: bool,
    pub multi_message_capable: u8,
    pub multi_message_enabled: u8,
    pub enabled: bool,
}

impl MsiInfo {
    pub fn max_vectors(&self) -> u8 {
        1 << self.multi_message_capable
    }

    pub fn allocated_vectors(&self) -> u8 {
        1 << self.multi_message_enabled
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsixInfo {
    pub offset: u8,
    pub table_size: u16,
    pub table_bar: u8,
    pub table_offset: u32,
    pub pba_bar: u8,
    pub pba_offset: u32,
    pub enabled: bool,
    pub function_mask: bool,
}

impl MsixInfo {
    pub fn vector_count(&self) -> u16 {
        self.table_size + 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerManagementInfo {
    pub offset: u8,
    pub version: u8,
    pub pme_clock: bool,
    pub dsi: bool,
    pub aux_current: u8,
    pub d1_support: bool,
    pub d2_support: bool,
    pub pme_support: u8,
    pub current_state: u8,
    pub no_soft_reset: bool,
    pub pme_enabled: bool,
    pub pme_status: bool,
}

impl PowerManagementInfo {
    pub fn supports_d1(&self) -> bool {
        self.d1_support
    }

    pub fn supports_d2(&self) -> bool {
        self.d2_support
    }

    pub fn supports_pme_from_d0(&self) -> bool {
        (self.pme_support & (1 << 0)) != 0
    }

    pub fn supports_pme_from_d1(&self) -> bool {
        (self.pme_support & (1 << 1)) != 0
    }

    pub fn supports_pme_from_d2(&self) -> bool {
        (self.pme_support & (1 << 2)) != 0
    }

    pub fn supports_pme_from_d3_hot(&self) -> bool {
        (self.pme_support & (1 << 3)) != 0
    }

    pub fn supports_pme_from_d3_cold(&self) -> bool {
        (self.pme_support & (1 << 4)) != 0
    }

    pub fn state_name(&self) -> &'static str {
        match self.current_state {
            0 => "D0",
            1 => "D1",
            2 => "D2",
            3 => "D3hot",
            _ => "Unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcieInfo {
    pub offset: u8,
    pub version: u8,
    pub device_type: PcieDeviceType,
    pub slot_implemented: bool,
    pub interrupt_message_number: u8,
    pub max_payload_size: u16,
    pub max_read_request_size: u16,
    pub link_speed: u8,
    pub link_width: u8,
    pub link_speed_supported: u8,
    pub link_width_supported: u8,
}

impl PcieInfo {
    pub fn link_speed_str(&self) -> &'static str {
        pcie_link_speed_str(self.link_speed)
    }

    pub fn bandwidth_gbps(&self) -> f32 {
        let speed_gbps = match self.link_speed {
            PCIE_LINK_SPEED_2_5GT => 2.5,
            PCIE_LINK_SPEED_5GT => 5.0,
            PCIE_LINK_SPEED_8GT => 8.0,
            PCIE_LINK_SPEED_16GT => 16.0,
            PCIE_LINK_SPEED_32GT => 32.0,
            PCIE_LINK_SPEED_64GT => 64.0,
            _ => 0.0,
        };

        let encoding_overhead = match self.link_speed {
            PCIE_LINK_SPEED_2_5GT | PCIE_LINK_SPEED_5GT => 0.8,
            _ => 0.9846,
        };

        speed_gbps * (self.link_width as f32) * encoding_overhead
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcieDeviceType {
    Endpoint,
    LegacyEndpoint,
    RootPort,
    UpstreamPort,
    DownstreamPort,
    PcieToPciBridge,
    PciToPcieBridge,
    RootComplexEndpoint,
    RootComplexEventCollector,
    Unknown(u8),
}

impl From<u8> for PcieDeviceType {
    fn from(value: u8) -> Self {
        match value {
            PCIE_TYPE_ENDPOINT => PcieDeviceType::Endpoint,
            PCIE_TYPE_LEGACY_ENDPOINT => PcieDeviceType::LegacyEndpoint,
            PCIE_TYPE_ROOT_PORT => PcieDeviceType::RootPort,
            PCIE_TYPE_UPSTREAM_PORT => PcieDeviceType::UpstreamPort,
            PCIE_TYPE_DOWNSTREAM_PORT => PcieDeviceType::DownstreamPort,
            PCIE_TYPE_PCIE_TO_PCI_BRIDGE => PcieDeviceType::PcieToPciBridge,
            PCIE_TYPE_PCI_TO_PCIE_BRIDGE => PcieDeviceType::PciToPcieBridge,
            PCIE_TYPE_ROOT_COMPLEX_ENDPOINT => PcieDeviceType::RootComplexEndpoint,
            PCIE_TYPE_ROOT_COMPLEX_EVENT_COLLECTOR => PcieDeviceType::RootComplexEventCollector,
            other => PcieDeviceType::Unknown(other),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PciDevice {
    pub address: PciAddress,
    pub device_id_info: DeviceId,
    pub class_code: ClassCode,
    pub header_type: HeaderType,
    pub multifunction: bool,
    pub bars: [PciBar; 6],
    pub capabilities: Vec<PciCapability>,
    pub pcie_capabilities: Vec<PcieCapability>,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub msi: Option<MsiInfo>,
    pub msix: Option<MsixInfo>,
    pub power_management: Option<PowerManagementInfo>,
    pub pcie: Option<PcieInfo>,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub progif: u8,
}

impl PciDevice {
    pub fn new(address: PciAddress) -> Self {
        Self {
            address,
            device_id_info: DeviceId::new(0xFFFF, 0xFFFF),
            class_code: ClassCode::new(0, 0, 0),
            header_type: HeaderType::Standard,
            multifunction: false,
            bars: [PciBar::NotPresent; 6],
            capabilities: Vec::new(),
            pcie_capabilities: Vec::new(),
            interrupt_line: 0xFF,
            interrupt_pin: 0,
            msi: None,
            msix: None,
            power_management: None,
            pcie: None,
            bus: address.bus,
            device: address.device,
            function: address.function,
            vendor_id: 0xFFFF,
            device_id: 0xFFFF,
            class: 0,
            subclass: 0,
            progif: 0,
        }
    }

    pub fn sync_compat_fields(&mut self) {
        self.bus = self.address.bus;
        self.device = self.address.device;
        self.function = self.address.function;
        self.vendor_id = self.device_id_info.vendor_id;
        self.device_id = self.device_id_info.device_id;
        self.class = self.class_code.class;
        self.subclass = self.class_code.subclass;
        self.progif = self.class_code.prog_if;
    }

    pub fn bus(&self) -> u8 {
        self.address.bus
    }

    pub fn device(&self) -> u8 {
        self.address.device
    }

    pub fn function(&self) -> u8 {
        self.address.function
    }

    pub fn vendor_id(&self) -> u16 {
        self.device_id_info.vendor_id
    }

    pub fn device_id_value(&self) -> u16 {
        self.device_id_info.device_id
    }

    pub fn class(&self) -> u8 {
        self.class_code.class
    }

    pub fn subclass(&self) -> u8 {
        self.class_code.subclass
    }

    pub fn prog_if(&self) -> u8 {
        self.class_code.prog_if
    }

    pub fn revision(&self) -> u8 {
        self.device_id_info.revision
    }

    pub fn get_bar(&self, index: usize) -> Option<&PciBar> {
        self.bars.get(index).filter(|b| b.is_present())
    }

    pub fn get_memory_bar(&self, index: usize) -> Option<PhysAddr> {
        self.bars.get(index).and_then(|b| b.address())
    }

    pub fn get_io_bar(&self, index: usize) -> Option<u16> {
        self.bars.get(index).and_then(|b| b.port())
    }

    pub fn find_capability(&self, id: u8) -> Option<&PciCapability> {
        self.capabilities.iter().find(|c| c.id == id)
    }

    pub fn has_capability(&self, id: u8) -> bool {
        self.capabilities.iter().any(|c| c.id == id)
    }

    pub fn supports_msi(&self) -> bool {
        self.msi.is_some()
    }

    pub fn supports_msix(&self) -> bool {
        self.msix.is_some()
    }

    pub fn is_pcie(&self) -> bool {
        self.pcie.is_some()
    }

    pub fn is_bridge(&self) -> bool {
        matches!(self.header_type, HeaderType::PciToPciBridge | HeaderType::CardBusBridge)
    }

    pub fn is_usb_controller(&self) -> bool {
        self.class_code.is_usb()
    }

    pub fn is_nvme_controller(&self) -> bool {
        self.class_code.is_nvme()
    }

    pub fn is_ahci_controller(&self) -> bool {
        self.class_code.is_ahci()
    }

    pub fn is_network_controller(&self) -> bool {
        self.class_code.is_network()
    }

    pub fn is_display_controller(&self) -> bool {
        self.class_code.is_display()
    }

    pub fn configure_msix(&mut self, irq_vector: u8) -> Result<(), super::error::PciError> {
        let msix = self.msix.as_ref().ok_or(super::error::PciError::MsixNotSupported)?;
        let config = super::config::ConfigSpace::new(self.address);
        super::msi::configure_msix(&config, msix, &self.bars, 0, irq_vector)?;
        super::msi::enable_msix(&config, msix)?;
        Ok(())
    }

    pub fn disable_msix(&mut self) -> Result<(), super::error::PciError> {
        let msix = self.msix.as_ref().ok_or(super::error::PciError::MsixNotSupported)?;
        let config = super::config::ConfigSpace::new(self.address);
        super::msi::disable_msix(&config, msix)
    }

    pub fn configure_msi(&mut self, irq_vector: u8) -> Result<(), super::error::PciError> {
        let msi = self.msi.as_ref().ok_or(super::error::PciError::MsiNotSupported)?;
        let config = super::config::ConfigSpace::new(self.address);
        super::msi::configure_msi(&config, msi, irq_vector)
    }

    pub fn disable_msi(&mut self) -> Result<(), super::error::PciError> {
        let msi = self.msi.as_ref().ok_or(super::error::PciError::MsiNotSupported)?;
        let config = super::config::ConfigSpace::new(self.address);
        super::msi::disable_msi(&config, msi)
    }
}

impl fmt::Display for PciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {:04x}:{:04x} {} [{}]",
            self.address,
            self.device_id_info.vendor_id,
            self.device_id_info.device_id,
            self.class_code,
            self.class_code.name()
        )
    }
}

#[derive(Clone, Debug)]
pub struct BridgeInfo {
    pub primary_bus: u8,
    pub secondary_bus: u8,
    pub subordinate_bus: u8,
    pub io_base: u32,
    pub io_limit: u32,
    pub memory_base: u32,
    pub memory_limit: u32,
    pub prefetch_base: u64,
    pub prefetch_limit: u64,
    pub bridge_control: u16,
}

impl BridgeInfo {
    pub fn new() -> Self {
        Self {
            primary_bus: 0,
            secondary_bus: 0,
            subordinate_bus: 0,
            io_base: 0,
            io_limit: 0,
            memory_base: 0,
            memory_limit: 0,
            prefetch_base: 0,
            prefetch_limit: 0,
            bridge_control: 0,
        }
    }

    pub fn io_window(&self) -> (u32, u32) {
        (self.io_base, self.io_limit)
    }

    pub fn memory_window(&self) -> (u32, u32) {
        (self.memory_base, self.memory_limit)
    }

    pub fn prefetch_window(&self) -> (u64, u64) {
        (self.prefetch_base, self.prefetch_limit)
    }
}

impl Default for BridgeInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiMessage {
    pub address: u64,
    pub data: u32,
}

impl MsiMessage {
    pub fn new(vector: u8, dest_id: u8, edge_trigger: bool, level_assert: bool) -> Self {
        let address = (MSI_ADDRESS_BASE as u64) | ((dest_id as u64) << MSI_ADDRESS_DEST_ID_SHIFT);
        let mut data = (vector as u32) & MSI_DATA_VECTOR_MASK;
        data |= MSI_DATA_DELIVERY_FIXED;
        if !edge_trigger {
            data |= MSI_DATA_TRIGGER_LEVEL;
            if level_assert {
                data |= MSI_DATA_LEVEL_ASSERT;
            }
        }
        Self { address, data }
    }

    pub fn for_local_apic(vector: u8) -> Self {
        Self::new(vector, 0, true, false)
    }
}
