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

use crate::drivers::pci::constants::*;

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
