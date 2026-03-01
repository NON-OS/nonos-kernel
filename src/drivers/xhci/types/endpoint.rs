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

use crate::drivers::xhci::constants::*;

#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct EpContext {
    dw0: u32,
    dw1: u32,
    dw2: u32,
    dw3: u32,
    dw4: u32,
    reserved: [u32; 3],
}

impl EpContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ep_state(&self) -> EpState {
        EpState::from_raw((self.dw0 & 0x7) as u8)
    }

    pub fn set_ep_state(&mut self, state: EpState) {
        self.dw0 = (self.dw0 & !0x7) | (state.to_raw() as u32);
    }

    pub fn mult(&self) -> u8 {
        ((self.dw0 >> 8) & 0x3) as u8
    }

    pub fn set_mult(&mut self, mult: u8) {
        self.dw0 = (self.dw0 & !(0x3 << 8)) | (((mult & 0x3) as u32) << 8);
    }

    pub fn max_primary_streams(&self) -> u8 {
        ((self.dw0 >> 10) & 0x1F) as u8
    }

    pub fn set_max_primary_streams(&mut self, streams: u8) {
        self.dw0 = (self.dw0 & !(0x1F << 10)) | (((streams & 0x1F) as u32) << 10);
    }

    pub fn lsa(&self) -> bool {
        (self.dw0 & (1 << 15)) != 0
    }

    pub fn set_lsa(&mut self, lsa: bool) {
        if lsa {
            self.dw0 |= 1 << 15;
        } else {
            self.dw0 &= !(1 << 15);
        }
    }

    pub fn interval(&self) -> u8 {
        ((self.dw0 >> 16) & 0xFF) as u8
    }

    pub fn set_interval(&mut self, interval: u8) {
        self.dw0 = (self.dw0 & !(0xFF << 16)) | ((interval as u32) << 16);
    }

    pub fn cerr(&self) -> u8 {
        ((self.dw1 >> 1) & 0x3) as u8
    }

    pub fn set_cerr(&mut self, cerr: u8) {
        self.dw1 = (self.dw1 & !(0x3 << 1)) | (((cerr & 0x3) as u32) << 1);
    }

    pub fn ep_type(&self) -> u8 {
        ((self.dw1 >> 3) & 0x7) as u8
    }

    pub fn set_ep_type(&mut self, ep_type: u8) {
        self.dw1 = (self.dw1 & !(0x7 << 3)) | (((ep_type & 0x7) as u32) << 3);
    }

    pub fn hid(&self) -> bool {
        (self.dw1 & (1 << 7)) != 0
    }

    pub fn set_hid(&mut self, hid: bool) {
        if hid {
            self.dw1 |= 1 << 7;
        } else {
            self.dw1 &= !(1 << 7);
        }
    }

    pub fn max_burst_size(&self) -> u8 {
        ((self.dw1 >> 8) & 0xFF) as u8
    }

    pub fn set_max_burst_size(&mut self, burst: u8) {
        self.dw1 = (self.dw1 & !(0xFF << 8)) | ((burst as u32) << 8);
    }

    pub fn max_packet_size(&self) -> u16 {
        ((self.dw1 >> 16) & 0xFFFF) as u16
    }

    pub fn set_max_packet_size(&mut self, mps: u16) {
        self.dw1 = (self.dw1 & !0xFFFF0000) | ((mps as u32) << 16);
    }

    pub fn tr_dequeue_pointer(&self) -> u64 {
        ((self.dw2 as u64) & !0xF) | ((self.dw3 as u64) << 32)
    }

    pub fn set_tr_dequeue_pointer(&mut self, ptr: u64, dcs: bool) {
        let low = ((ptr & 0xFFFF_FFF0) as u32) | (if dcs { 1 } else { 0 });
        self.dw2 = low;
        self.dw3 = (ptr >> 32) as u32;
    }

    pub fn dcs(&self) -> bool {
        (self.dw2 & 1) != 0
    }

    pub fn average_trb_length(&self) -> u16 {
        (self.dw4 & 0xFFFF) as u16
    }

    pub fn set_average_trb_length(&mut self, len: u16) {
        self.dw4 = (self.dw4 & !0xFFFF) | (len as u32);
    }

    pub fn max_esit_payload(&self) -> u32 {
        let lo = ((self.dw4 >> 16) & 0xFFFF) as u32;
        let hi = ((self.dw0 >> 24) & 0xFF) as u32;
        lo | (hi << 16)
    }

    pub fn set_max_esit_payload(&mut self, payload: u32) {
        let lo = (payload & 0xFFFF) as u32;
        let hi = ((payload >> 16) & 0xFF) as u32;
        self.dw4 = (self.dw4 & 0xFFFF) | (lo << 16);
        self.dw0 = (self.dw0 & !(0xFF << 24)) | (hi << 24);
    }

    pub fn configure_control(&mut self, max_packet_size: u16) {
        self.set_ep_type(EP_TYPE_CONTROL);
        self.set_max_packet_size(max_packet_size);
        self.set_cerr(3);
        self.set_max_burst_size(0);
        self.set_average_trb_length(8);
    }

    pub fn configure_bulk(&mut self, is_in: bool, max_packet_size: u16, max_burst: u8) {
        let ep_type = if is_in {
            EP_TYPE_BULK_IN
        } else {
            EP_TYPE_BULK_OUT
        };
        self.set_ep_type(ep_type);
        self.set_max_packet_size(max_packet_size);
        self.set_max_burst_size(max_burst);
        self.set_cerr(3);
        self.set_average_trb_length(max_packet_size);
    }

    pub fn configure_interrupt(&mut self, is_in: bool, max_packet_size: u16, interval: u8) {
        let ep_type = if is_in {
            EP_TYPE_INTERRUPT_IN
        } else {
            EP_TYPE_INTERRUPT_OUT
        };
        self.set_ep_type(ep_type);
        self.set_max_packet_size(max_packet_size);
        self.set_interval(interval);
        self.set_cerr(3);
        self.set_average_trb_length(max_packet_size);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpState {
    Disabled,
    Running,
    Halted,
    Stopped,
    Error,
    Reserved(u8),
}

impl EpState {
    pub(crate) fn from_raw(val: u8) -> Self {
        match val {
            0 => EpState::Disabled,
            1 => EpState::Running,
            2 => EpState::Halted,
            3 => EpState::Stopped,
            4 => EpState::Error,
            v => EpState::Reserved(v),
        }
    }

    pub(crate) fn to_raw(self) -> u8 {
        match self {
            EpState::Disabled => 0,
            EpState::Running => 1,
            EpState::Halted => 2,
            EpState::Stopped => 3,
            EpState::Error => 4,
            EpState::Reserved(v) => v,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EpContextWithPad {
    pub context: EpContext,
    _pad: [u8; 32],
}

impl Default for EpContextWithPad {
    fn default() -> Self {
        Self {
            context: EpContext::default(),
            _pad: [0; 32],
        }
    }
}
