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
use super::base::Trb;

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
