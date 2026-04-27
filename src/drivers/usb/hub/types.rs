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

use super::constants::MAX_HUB_PORTS;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct HubDescriptor {
    pub length: u8,
    pub desc_type: u8,
    pub num_ports: u8,
    pub characteristics: u16,
    pub power_on_delay: u8,
    pub hub_ctrl_current: u8,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PortStatus {
    pub status: u16,
    pub change: u16,
}

impl PortStatus {
    pub fn from_bytes(status: u16, change: u16) -> Self {
        Self { status, change }
    }
}

impl PortStatus {
    pub fn connected(&self) -> bool {
        (self.status & super::constants::PORT_STAT_CONNECTION) != 0
    }
    pub fn enabled(&self) -> bool {
        (self.status & super::constants::PORT_STAT_ENABLE) != 0
    }
    pub fn suspended(&self) -> bool {
        (self.status & super::constants::PORT_STAT_SUSPEND) != 0
    }
    pub fn overcurrent(&self) -> bool {
        (self.status & super::constants::PORT_STAT_OVERCURRENT) != 0
    }
    pub fn reset_active(&self) -> bool {
        (self.status & super::constants::PORT_STAT_RESET) != 0
    }
    pub fn powered(&self) -> bool {
        (self.status & super::constants::PORT_STAT_POWER) != 0
    }
    pub fn low_speed(&self) -> bool {
        (self.status & super::constants::PORT_STAT_LOW_SPEED) != 0
    }
    pub fn high_speed(&self) -> bool {
        (self.status & super::constants::PORT_STAT_HIGH_SPEED) != 0
    }
    pub fn connection_changed(&self) -> bool {
        (self.change & 0x0001) != 0
    }
    pub fn enable_changed(&self) -> bool {
        (self.change & 0x0002) != 0
    }
    pub fn reset_changed(&self) -> bool {
        (self.change & 0x0010) != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Disconnected,
    Powered,
    Connected,
    Enabled,
    Suspended,
    Error,
}

#[derive(Debug, Clone)]
pub struct HubState {
    pub address: u8,
    pub num_ports: u8,
    pub power_on_delay_ms: u8,
    pub port_states: [PortState; MAX_HUB_PORTS],
    pub port_devices: [Option<u8>; MAX_HUB_PORTS],
    pub is_root: bool,
    pub depth: u8,
}

impl HubState {
    pub fn new(address: u8, num_ports: u8, delay_ms: u8, is_root: bool, depth: u8) -> Self {
        Self {
            address,
            num_ports,
            power_on_delay_ms: delay_ms,
            is_root,
            depth,
            port_states: [PortState::Disconnected; MAX_HUB_PORTS],
            port_devices: [None; MAX_HUB_PORTS],
        }
    }
}
