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

use super::constants::*;
use super::error::{XhciError, XhciResult};
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

pub struct NormalTrbBuilder {
    trb: Trb,
}

impl NormalTrbBuilder {
    pub fn new() -> Self {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_NORMAL);
        Self { trb }
    }

    pub fn data_buffer(mut self, phys_addr: u64, length: u32) -> Self {
        self.trb.set_pointer(phys_addr);
        self.trb.set_transfer_length(length);
        self
    }

    pub fn ioc(mut self, ioc: bool) -> Self {
        self.trb.set_ioc(ioc);
        self
    }

    pub fn chain(mut self, chain: bool) -> Self {
        self.trb.set_chain(chain);
        self
    }

    pub fn cycle(mut self, cycle: bool) -> Self {
        self.trb.set_cycle(cycle);
        self
    }

    pub fn build(self) -> Trb {
        self.trb
    }
}

impl Default for NormalTrbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SetupStageTrbBuilder {
    trb: Trb,
}

impl SetupStageTrbBuilder {
    pub fn new() -> Self {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_SETUP_STAGE);
        Self { trb }
    }

    pub fn setup_packet(
        mut self,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        w_length: u16,
    ) -> Self {
        self.trb.d0 =
            (bm_request_type as u32) | ((b_request as u32) << 8) | ((w_value as u32) << 16);
        self.trb.d1 = (w_index as u32) | ((w_length as u32) << 16);
        self
    }

    pub fn transfer_type(mut self, has_data: bool, is_in: bool) -> Self {
        let trt = if !has_data {
            TRT_NO_DATA
        } else if is_in {
            TRT_IN_DATA
        } else {
            TRT_OUT_DATA
        };
        self.trb.d2 = (self.trb.d2 & !0x30000) | trt;
        self
    }

    pub fn cycle(mut self, cycle: bool) -> Self {
        self.trb.set_cycle(cycle);
        self
    }

    pub fn build(self) -> Trb {
        self.trb
    }
}

impl Default for SetupStageTrbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DataStageTrbBuilder {
    trb: Trb,
}

impl DataStageTrbBuilder {
    pub fn new() -> Self {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_DATA_STAGE);
        Self { trb }
    }

    pub fn data_buffer(mut self, phys_addr: u64, length: u32) -> Self {
        self.trb.set_pointer(phys_addr);
        self.trb.set_transfer_length(length);
        self
    }

    pub fn direction_in(mut self, is_in: bool) -> Self {
        if is_in {
            self.trb.d3 |= TRB_DIR_IN;
        } else {
            self.trb.d3 &= !TRB_DIR_IN;
        }
        self
    }

    pub fn ioc(mut self, ioc: bool) -> Self {
        self.trb.set_ioc(ioc);
        self
    }

    pub fn cycle(mut self, cycle: bool) -> Self {
        self.trb.set_cycle(cycle);
        self
    }

    pub fn build(self) -> Trb {
        self.trb
    }
}

impl Default for DataStageTrbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct StatusStageTrbBuilder {
    trb: Trb,
}

impl StatusStageTrbBuilder {
    pub fn new() -> Self {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_STATUS_STAGE);
        Self { trb }
    }

    pub fn direction_in(mut self, is_in: bool) -> Self {
        if is_in {
            self.trb.d3 |= TRB_DIR_IN;
        } else {
            self.trb.d3 &= !TRB_DIR_IN;
        }
        self
    }

    pub fn ioc(mut self, ioc: bool) -> Self {
        self.trb.set_ioc(ioc);
        self
    }

    pub fn cycle(mut self, cycle: bool) -> Self {
        self.trb.set_cycle(cycle);
        self
    }

    pub fn build(self) -> Trb {
        self.trb
    }
}

impl Default for StatusStageTrbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LinkTrbBuilder {
    trb: Trb,
}

impl LinkTrbBuilder {
    pub fn new() -> Self {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_LINK);
        Self { trb }
    }

    pub fn target(mut self, phys_addr: u64) -> Self {
        self.trb.set_pointer(phys_addr);
        self
    }

    pub fn toggle_cycle(mut self, toggle: bool) -> Self {
        if toggle {
            self.trb.d3 |= LINK_TC;
        } else {
            self.trb.d3 &= !LINK_TC;
        }
        self
    }

    pub fn cycle(mut self, cycle: bool) -> Self {
        self.trb.set_cycle(cycle);
        self
    }

    pub fn build(self) -> Trb {
        self.trb
    }
}

impl Default for LinkTrbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub fn enable_slot_command(cycle: bool) -> Trb {
    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_ENABLE_SLOT_CMD);
    trb.set_cycle(cycle);
    trb
}

pub fn disable_slot_command(slot_id: u8, cycle: bool) -> Trb {
    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_DISABLE_SLOT_CMD);
    trb.d3 |= (slot_id as u32) << 24;
    trb.set_cycle(cycle);
    trb
}

pub fn address_device_command(input_context_phys: u64, slot_id: u8, bsr: bool, cycle: bool) -> Trb {
    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_ADDRESS_DEVICE_CMD);
    trb.set_pointer(input_context_phys);
    trb.d3 |= (slot_id as u32) << 24;
    if bsr {
        trb.d3 |= 1 << 9;
    }
    trb.set_cycle(cycle);
    trb
}

pub fn configure_endpoint_command(
    input_context_phys: u64,
    slot_id: u8,
    deconfigure: bool,
    cycle: bool,
) -> Trb {
    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_CONFIGURE_EP_CMD);
    trb.set_pointer(input_context_phys);
    trb.d3 |= (slot_id as u32) << 24;
    if deconfigure {
        trb.d3 |= 1 << 9;
    }
    trb.set_cycle(cycle);
    trb
}

pub fn evaluate_context_command(input_context_phys: u64, slot_id: u8, cycle: bool) -> Trb {
    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_EVALUATE_CTX_CMD);
    trb.set_pointer(input_context_phys);
    trb.d3 |= (slot_id as u32) << 24;
    trb.set_cycle(cycle);
    trb
}

pub fn reset_endpoint_command(slot_id: u8, endpoint_id: u8, tsp: bool, cycle: bool) -> Trb {
    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_RESET_EP_CMD);
    trb.d3 |= (slot_id as u32) << 24;
    trb.d3 |= (endpoint_id as u32) << 16;
    if tsp {
        trb.d3 |= 1 << 9;
    }
    trb.set_cycle(cycle);
    trb
}

pub fn stop_endpoint_command(slot_id: u8, endpoint_id: u8, suspend: bool, cycle: bool) -> Trb {
    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_STOP_EP_CMD);
    trb.d3 |= (slot_id as u32) << 24;
    trb.d3 |= (endpoint_id as u32) << 16;
    if suspend {
        trb.d3 |= 1 << 23;
    }
    trb.set_cycle(cycle);
    trb
}

pub fn set_tr_dequeue_command(
    new_dequeue_ptr: u64,
    slot_id: u8,
    endpoint_id: u8,
    stream_id: u16,
    dcs: bool,
    cycle: bool,
) -> Trb {
    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_SET_TR_DEQUEUE_CMD);
    let ptr_with_dcs = (new_dequeue_ptr & !0xF) | (if dcs { 1 } else { 0 });
    trb.set_pointer(ptr_with_dcs);
    trb.d2 = (stream_id as u32) << 16;
    trb.d3 |= (slot_id as u32) << 24;
    trb.d3 |= (endpoint_id as u32) << 16;
    trb.set_cycle(cycle);
    trb
}

pub fn reset_device_command(slot_id: u8, cycle: bool) -> Trb {
    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_RESET_DEVICE_CMD);
    trb.d3 |= (slot_id as u32) << 24;
    trb.set_cycle(cycle);
    trb
}

pub fn noop_command(cycle: bool) -> Trb {
    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_NOOP_CMD);
    trb.set_cycle(cycle);
    trb
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_trb_size() {
        assert_eq!(mem::size_of::<Trb>(), 16);
    }

    #[test]
    fn test_trb_alignment() {
        assert_eq!(mem::align_of::<Trb>(), 16);
    }

    #[test]
    fn test_trb_type() {
        let mut trb = Trb::new();
        trb.set_type(TRB_TYPE_NORMAL);
        assert_eq!(trb.get_type(), TRB_TYPE_NORMAL);

        trb.set_type(TRB_TYPE_LINK);
        assert_eq!(trb.get_type(), TRB_TYPE_LINK);
    }

    #[test]
    fn test_trb_cycle() {
        let mut trb = Trb::new();
        assert!(!trb.get_cycle());

        trb.set_cycle(true);
        assert!(trb.get_cycle());

        trb.set_cycle(false);
        assert!(!trb.get_cycle());
    }

    #[test]
    fn test_trb_pointer() {
        let mut trb = Trb::new();
        let ptr = 0x1234_5678_9ABC_DEF0u64;
        trb.set_pointer(ptr);
        assert_eq!(trb.get_pointer(), ptr);
    }

    #[test]
    fn test_setup_stage_builder() {
        let trb = SetupStageTrbBuilder::new()
            .setup_packet(0x80, 0x06, 0x0100, 0x0000, 18)
            .transfer_type(true, true)
            .cycle(true)
            .build();

        assert_eq!(trb.get_type(), TRB_TYPE_SETUP_STAGE);
        assert!(trb.get_cycle());
    }

    #[test]
    fn test_enable_slot_command() {
        let trb = enable_slot_command(true);
        assert_eq!(trb.get_type(), TRB_TYPE_ENABLE_SLOT_CMD);
        assert!(trb.get_cycle());
    }

    #[test]
    fn test_pointer_alignment_validation() {
        assert!(Trb::validate_pointer_alignment(0x1000).is_ok());
        assert!(Trb::validate_pointer_alignment(0x1010).is_ok());
        assert!(Trb::validate_pointer_alignment(0x1001).is_err());
    }
}
