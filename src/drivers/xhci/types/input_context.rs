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

use crate::drivers::xhci::constants::EP_TYPE_CONTROL;
use super::endpoint::{EpContext, EpContextWithPad};
use super::slot::SlotContext;

#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InputControlContext {
    pub drop_flags: u32,
    pub add_flags: u32,
    reserved: [u32; 5],
    dw7: u32,
}

impl InputControlContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_context(&mut self, index: u8) {
        if index < 32 {
            self.add_flags |= 1 << index;
        }
    }

    pub fn drop_context(&mut self, index: u8) {
        if index < 32 {
            self.drop_flags |= 1 << index;
        }
    }

    pub fn is_adding(&self, index: u8) -> bool {
        if index < 32 {
            (self.add_flags & (1 << index)) != 0
        } else {
            false
        }
    }

    pub fn is_dropping(&self, index: u8) -> bool {
        if index < 32 {
            (self.drop_flags & (1 << index)) != 0
        } else {
            false
        }
    }

    pub fn configuration_value(&self) -> u8 {
        (self.dw7 & 0xFF) as u8
    }

    pub fn set_configuration_value(&mut self, value: u8) {
        self.dw7 = (self.dw7 & !0xFF) | (value as u32);
    }

    pub fn interface_number(&self) -> u8 {
        ((self.dw7 >> 8) & 0xFF) as u8
    }

    pub fn set_interface_number(&mut self, num: u8) {
        self.dw7 = (self.dw7 & !(0xFF << 8)) | ((num as u32) << 8);
    }

    pub fn alternate_setting(&self) -> u8 {
        ((self.dw7 >> 16) & 0xFF) as u8
    }

    pub fn set_alternate_setting(&mut self, setting: u8) {
        self.dw7 = (self.dw7 & !(0xFF << 16)) | ((setting as u32) << 16);
    }
}

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct InputContext {
    pub icc: InputControlContext,
    _icc_pad: [u8; 32],
    pub slot: SlotContext,
    _slot_pad: [u8; 32],
    pub ep0: EpContext,
    _ep0_pad: [u8; 32],
    pub endpoints: [EpContextWithPad; 30],
}

impl Default for InputContext {
    fn default() -> Self {
        Self {
            icc: InputControlContext::default(),
            _icc_pad: [0; 32],
            slot: SlotContext::default(),
            _slot_pad: [0; 32],
            ep0: EpContext::default(),
            _ep0_pad: [0; 32],
            endpoints: [EpContextWithPad::default(); 30],
        }
    }
}

impl InputContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_endpoint_mut(&mut self, dci: u8) -> Option<&mut EpContext> {
        match dci {
            0 => None,
            1 => Some(&mut self.ep0),
            2..=31 => Some(&mut self.endpoints[(dci - 2) as usize].context),
            _ => None,
        }
    }

    pub fn configure_for_address_device(&mut self, port: u8, speed: u8, max_packet_size: u16) {
        self.icc.add_flags = 0b11;
        self.icc.drop_flags = 0;

        self.slot.set_route_string(0);
        self.slot.set_speed(speed);
        self.slot.set_root_hub_port(port);
        self.slot.set_context_entries(1);

        self.ep0.set_ep_type(EP_TYPE_CONTROL);
        self.ep0.set_max_packet_size(max_packet_size);
        self.ep0.set_cerr(3);
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}
