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

use super::super::constants::*;
use super::super::error::{XhciError, XhciResult};

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug)]
pub struct Trb {
    pub d0: u32,
    pub d1: u32,
    pub d2: u32,
    pub d3: u32,
}

impl Default for Trb {
    fn default() -> Self {
        Trb {
            d0: 0,
            d1: 0,
            d2: 0,
            d3: 0,
        }
    }
}

impl Trb {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn get_type(&self) -> u32 {
        (self.d3 >> TRB_TYPE_SHIFT) & 0x3F
    }

    #[inline]
    pub fn set_type(&mut self, trb_type: u32) {
        self.d3 = (self.d3 & !TRB_TYPE_MASK) | ((trb_type & 0x3F) << TRB_TYPE_SHIFT);
    }

    #[inline]
    pub fn get_cycle(&self) -> bool {
        (self.d3 & TRB_CYCLE) != 0
    }

    #[inline]
    pub fn set_cycle(&mut self, cycle: bool) {
        if cycle {
            self.d3 |= TRB_CYCLE;
        } else {
            self.d3 &= !TRB_CYCLE;
        }
    }

    #[inline]
    pub fn ioc(&self) -> bool {
        (self.d3 & TRB_IOC) != 0
    }

    #[inline]
    pub fn set_ioc(&mut self, ioc: bool) {
        if ioc {
            self.d3 |= TRB_IOC;
        } else {
            self.d3 &= !TRB_IOC;
        }
    }

    #[inline]
    pub fn chain(&self) -> bool {
        (self.d3 & TRB_CH) != 0
    }

    #[inline]
    pub fn set_chain(&mut self, chain: bool) {
        if chain {
            self.d3 |= TRB_CH;
        } else {
            self.d3 &= !TRB_CH;
        }
    }

    #[inline]
    pub fn get_pointer(&self) -> u64 {
        (self.d0 as u64) | ((self.d1 as u64) << 32)
    }

    #[inline]
    pub fn set_pointer(&mut self, ptr: u64) {
        self.d0 = (ptr & 0xFFFF_FFFF) as u32;
        self.d1 = (ptr >> 32) as u32;
    }

    #[inline]
    pub fn get_transfer_length(&self) -> u32 {
        self.d2 & 0x1FFFF
    }

    #[inline]
    pub fn set_transfer_length(&mut self, len: u32) {
        self.d2 = (self.d2 & !0x1FFFF) | (len & 0x1FFFF);
    }

    pub fn validate_transfer_type(&self) -> XhciResult<()> {
        let trb_type = self.get_type();
        if VALID_TRANSFER_TRB_TYPES.contains(&trb_type) {
            Ok(())
        } else {
            Err(XhciError::InvalidTrbType(trb_type))
        }
    }

    pub fn validate_command_type(&self) -> XhciResult<()> {
        let trb_type = self.get_type();
        if VALID_COMMAND_TRB_TYPES.contains(&trb_type) {
            Ok(())
        } else {
            Err(XhciError::InvalidTrbType(trb_type))
        }
    }

    pub fn validate_pointer_alignment(ptr: u64) -> XhciResult<()> {
        if ptr % TRB_ALIGNMENT != 0 {
            Err(XhciError::TrbMisaligned(ptr))
        } else {
            Ok(())
        }
    }

    #[inline]
    pub fn completion_code(&self) -> u8 {
        ((self.d2 >> 24) & 0xFF) as u8
    }

    #[inline]
    pub fn slot_id(&self) -> u8 {
        ((self.d3 >> 24) & 0xFF) as u8
    }

    #[inline]
    pub fn endpoint_id(&self) -> u8 {
        ((self.d3 >> 16) & 0x1F) as u8
    }

    #[inline]
    pub fn transfer_length_remaining(&self) -> u32 {
        self.d2 & 0xFFFFFF
    }

    pub fn validate_completion(&self, expected_ptr: u64) -> XhciResult<u8> {
        let trb_type = self.get_type();

        if trb_type != TRB_TYPE_CMD_COMPLETION_EVENT && trb_type != TRB_TYPE_TRANSFER_EVENT {
            return Err(XhciError::InvalidCompletion);
        }

        let event_trb_ptr = self.get_pointer();
        if (event_trb_ptr & !0xF) != (expected_ptr & !0xF) {
            return Err(XhciError::InvalidCompletion);
        }

        Ok(self.completion_code())
    }

    pub fn is_success(&self) -> bool {
        self.completion_code() == CC_SUCCESS
    }

    pub fn clear(&mut self) {
        self.d0 = 0;
        self.d1 = 0;
        self.d2 = 0;
        self.d3 = 0;
    }
}
