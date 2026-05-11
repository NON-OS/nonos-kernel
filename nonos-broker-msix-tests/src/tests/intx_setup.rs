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

//! INTx test scaffolding: a claimed device with `irq_pin = 1` and
//! `irq_line = 11`, plus the matching wire-form `DeviceRecord` so
//! `bind_intx`'s `table::list().find(...)` lookup succeeds.

use alloc::vec;

use crate::broker::claim;
use crate::broker::device::{Bar, DeviceRecord, BUS_KIND_PCI};
use crate::broker::irq::types::IrqBindRequest;
use crate::broker::table;
use crate::fixtures::reset::reset_all;

pub const PID: u32 = 9;
pub const DEVICE_ID: u64 = 200;
pub const IRQ_LINE: u8 = 11;
pub const IRQ_PIN: u8 = 1;

pub fn fresh() -> u64 {
    reset_all();
    table::install_for_test(vec![record()]);
    claim::install_for_test(PID, DEVICE_ID)
}

pub fn record() -> DeviceRecord {
    DeviceRecord {
        device_id: DEVICE_ID,
        bus_kind: BUS_KIND_PCI,
        _pad0: [0; 3],
        class: 0,
        vendor: 0x1AF4,
        device: 0x1000,
        flags: 0,
        bar_count: 0,
        irq_line: IRQ_LINE,
        irq_pin: IRQ_PIN,
        _pad1: [0; 5],
        bars: [Bar::empty(); 6],
    }
}

pub fn intx_request(epoch: u64) -> IrqBindRequest {
    IrqBindRequest {
        device_id: DEVICE_ID,
        claim_epoch: epoch,
        irq_source: IRQ_LINE as u32,
        flags: 0,
        vector_count: 0,
    }
}
