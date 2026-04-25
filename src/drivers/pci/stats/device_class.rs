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

#[derive(Debug, Clone)]
pub struct DeviceClassStats {
    pub unclassified: u64,
    pub mass_storage: u64,
    pub network: u64,
    pub display: u64,
    pub multimedia: u64,
    pub memory: u64,
    pub bridge: u64,
    pub simple_comm: u64,
    pub base_peripheral: u64,
    pub input: u64,
    pub docking: u64,
    pub processor: u64,
    pub serial_bus: u64,
    pub wireless: u64,
    pub intelligent_io: u64,
    pub satellite_comm: u64,
    pub encryption: u64,
    pub signal_processing: u64,
    pub other: u64,
}

impl DeviceClassStats {
    pub fn new() -> Self {
        Self {
            unclassified: 0,
            mass_storage: 0,
            network: 0,
            display: 0,
            multimedia: 0,
            memory: 0,
            bridge: 0,
            simple_comm: 0,
            base_peripheral: 0,
            input: 0,
            docking: 0,
            processor: 0,
            serial_bus: 0,
            wireless: 0,
            intelligent_io: 0,
            satellite_comm: 0,
            encryption: 0,
            signal_processing: 0,
            other: 0,
        }
    }

    pub fn record_device(&mut self, class: u8) {
        use super::super::constants::*;
        match class {
            CLASS_UNCLASSIFIED => self.unclassified += 1,
            CLASS_MASS_STORAGE => self.mass_storage += 1,
            CLASS_NETWORK => self.network += 1,
            CLASS_DISPLAY => self.display += 1,
            CLASS_MULTIMEDIA => self.multimedia += 1,
            CLASS_MEMORY => self.memory += 1,
            CLASS_BRIDGE => self.bridge += 1,
            CLASS_SIMPLE_COMM => self.simple_comm += 1,
            CLASS_BASE_PERIPHERAL => self.base_peripheral += 1,
            CLASS_INPUT => self.input += 1,
            CLASS_DOCKING => self.docking += 1,
            CLASS_PROCESSOR => self.processor += 1,
            CLASS_SERIAL_BUS => self.serial_bus += 1,
            CLASS_WIRELESS => self.wireless += 1,
            CLASS_INTELLIGENT_IO => self.intelligent_io += 1,
            CLASS_SATELLITE_COMM => self.satellite_comm += 1,
            CLASS_ENCRYPTION => self.encryption += 1,
            CLASS_SIGNAL_PROCESSING => self.signal_processing += 1,
            _ => self.other += 1,
        }
    }

    pub fn total(&self) -> u64 {
        self.unclassified
            + self.mass_storage
            + self.network
            + self.display
            + self.multimedia
            + self.memory
            + self.bridge
            + self.simple_comm
            + self.base_peripheral
            + self.input
            + self.docking
            + self.processor
            + self.serial_bus
            + self.wireless
            + self.intelligent_io
            + self.satellite_comm
            + self.encryption
            + self.signal_processing
            + self.other
    }
}

impl Default for DeviceClassStats {
    fn default() -> Self {
        Self::new()
    }
}
