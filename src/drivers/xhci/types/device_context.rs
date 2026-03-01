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

use super::endpoint::{EpContext, EpContextWithPad};
use super::slot::SlotContext;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct DeviceContext {
    pub slot: SlotContext,
    _slot_pad: [u8; 32],
    pub ep0: EpContext,
    _ep0_pad: [u8; 32],
    pub endpoints: [EpContextWithPad; 30],
}

impl Default for DeviceContext {
    fn default() -> Self {
        Self {
            slot: SlotContext::default(),
            _slot_pad: [0; 32],
            ep0: EpContext::default(),
            _ep0_pad: [0; 32],
            endpoints: [EpContextWithPad::default(); 30],
        }
    }
}

impl DeviceContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_endpoint(&self, dci: u8) -> Option<&EpContext> {
        match dci {
            0 => None,
            1 => Some(&self.ep0),
            2..=31 => Some(&self.endpoints[(dci - 2) as usize].context),
            _ => None,
        }
    }

    pub fn get_endpoint_mut(&mut self, dci: u8) -> Option<&mut EpContext> {
        match dci {
            0 => None,
            1 => Some(&mut self.ep0),
            2..=31 => Some(&mut self.endpoints[(dci - 2) as usize].context),
            _ => None,
        }
    }

    pub fn ep_addr_to_dci(ep_addr: u8) -> u8 {
        let ep_num = ep_addr & 0x0F;
        let is_in = (ep_addr & 0x80) != 0;
        if ep_num == 0 {
            1
        } else {
            ep_num * 2 + if is_in { 1 } else { 0 }
        }
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}
