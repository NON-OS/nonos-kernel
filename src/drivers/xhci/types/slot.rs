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

#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct SlotContext {
    dw0: u32,
    dw1: u32,
    dw2: u32,
    dw3: u32,
    reserved: [u32; 4],
}

impl SlotContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn route_string(&self) -> u32 {
        self.dw0 & 0xFFFFF
    }

    pub fn set_route_string(&mut self, route: u32) {
        self.dw0 = (self.dw0 & !0xFFFFF) | (route & 0xFFFFF);
    }

    pub fn speed(&self) -> u8 {
        ((self.dw0 >> 20) & 0xF) as u8
    }

    pub fn set_speed(&mut self, speed: u8) {
        self.dw0 = (self.dw0 & !(0xF << 20)) | (((speed & 0xF) as u32) << 20);
    }

    pub fn mtt(&self) -> bool {
        (self.dw0 & (1 << 25)) != 0
    }

    pub fn set_mtt(&mut self, mtt: bool) {
        if mtt {
            self.dw0 |= 1 << 25;
        } else {
            self.dw0 &= !(1 << 25);
        }
    }

    pub fn hub(&self) -> bool {
        (self.dw0 & (1 << 26)) != 0
    }

    pub fn set_hub(&mut self, hub: bool) {
        if hub {
            self.dw0 |= 1 << 26;
        } else {
            self.dw0 &= !(1 << 26);
        }
    }

    pub fn context_entries(&self) -> u8 {
        ((self.dw0 >> 27) & 0x1F) as u8
    }

    pub fn set_context_entries(&mut self, entries: u8) {
        self.dw0 = (self.dw0 & !(0x1F << 27)) | (((entries & 0x1F) as u32) << 27);
    }

    pub fn max_exit_latency(&self) -> u16 {
        (self.dw1 & 0xFFFF) as u16
    }

    pub fn set_max_exit_latency(&mut self, latency: u16) {
        self.dw1 = (self.dw1 & !0xFFFF) | (latency as u32);
    }

    pub fn root_hub_port(&self) -> u8 {
        ((self.dw1 >> 16) & 0xFF) as u8
    }

    pub fn set_root_hub_port(&mut self, port: u8) {
        self.dw1 = (self.dw1 & !(0xFF << 16)) | ((port as u32) << 16);
    }

    pub fn num_ports(&self) -> u8 {
        ((self.dw1 >> 24) & 0xFF) as u8
    }

    pub fn set_num_ports(&mut self, ports: u8) {
        self.dw1 = (self.dw1 & !(0xFF << 24)) | ((ports as u32) << 24);
    }

    pub fn tt_hub_slot_id(&self) -> u8 {
        (self.dw2 & 0xFF) as u8
    }

    pub fn set_tt_hub_slot_id(&mut self, slot: u8) {
        self.dw2 = (self.dw2 & !0xFF) | (slot as u32);
    }

    pub fn tt_port_number(&self) -> u8 {
        ((self.dw2 >> 8) & 0xFF) as u8
    }

    pub fn set_tt_port_number(&mut self, port: u8) {
        self.dw2 = (self.dw2 & !(0xFF << 8)) | ((port as u32) << 8);
    }

    pub fn ttt(&self) -> u8 {
        ((self.dw2 >> 16) & 0x3) as u8
    }

    pub fn set_ttt(&mut self, ttt: u8) {
        self.dw2 = (self.dw2 & !(0x3 << 16)) | (((ttt & 0x3) as u32) << 16);
    }

    pub fn interrupter_target(&self) -> u16 {
        ((self.dw2 >> 22) & 0x3FF) as u16
    }

    pub fn set_interrupter_target(&mut self, target: u16) {
        self.dw2 = (self.dw2 & !(0x3FF << 22)) | (((target & 0x3FF) as u32) << 22);
    }

    pub fn usb_device_address(&self) -> u8 {
        (self.dw3 & 0xFF) as u8
    }

    pub fn set_usb_device_address(&mut self, addr: u8) {
        self.dw3 = (self.dw3 & !0xFF) | (addr as u32);
    }

    pub fn slot_state(&self) -> SlotState {
        SlotState::from_raw(((self.dw3 >> 27) & 0x1F) as u8)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Disabled,
    Default,
    Addressed,
    Configured,
    Reserved(u8),
}

impl SlotState {
    fn from_raw(val: u8) -> Self {
        match val {
            0 => SlotState::Disabled,
            1 => SlotState::Default,
            2 => SlotState::Addressed,
            3 => SlotState::Configured,
            v => SlotState::Reserved(v),
        }
    }
}
