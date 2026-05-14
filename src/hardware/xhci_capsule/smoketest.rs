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

// P0 boot proof. The capsule has already issued a No-op and seen
// its completion event by the time `driver.xhci0` is advertised.
// Here we cross-check: capsule alive, healthcheck, controller
// running (HCH=0) with DCBAA programmed and the No-op drained,
// port_status bounded by max_ports. PASS means controller-up,
// nothing more.

use crate::services::lifecycle::smoketest_log;

use super::client;
use super::error::DriverXhciError;
use super::smoketest_slot::{prove_slot_lifecycle, SlotProofError};
use super::state;

const TAG: &[u8] = b"[DRIVER-XHCI-TEST] ";
const USBSTS_HCH: u32 = 1 << 0;

pub fn run() {
    if !state::is_alive() {
        return fail_msg(b"capsule not alive");
    }
    mark(b"capsule alive");

    if let Err(e) = client::healthcheck() {
        return fail(b"healthcheck", e);
    }
    mark(b"healthcheck ok");

    let cs = match client::controller_status() {
        Ok(s) => s,
        Err(e) => return fail(b"controller_status", e),
    };
    if cs.usbsts & USBSTS_HCH != 0 {
        return fail_msg(b"controller halted (USBSTS.HCH=1)");
    }
    if cs.max_slots == 0 {
        return fail_msg(b"max_slots==0");
    }
    if cs.dcbaa_phys == 0 {
        return fail_msg(b"DCBAA not programmed");
    }
    if cs.scratchpad_pages_alloc != cs.max_scratchpad {
        return fail_msg(b"scratchpad page count mismatch");
    }
    if cs.events_drained_total == 0 {
        return fail_msg(b"no events drained, No-op completion not seen");
    }
    mark(b"controller_status ok");

    if let Err(e) = prove_slot_lifecycle(cs.max_slots, cs.allocated_slots) {
        return fail_slot(e);
    }
    mark(b"slot enable/disable ok");

    let ports = match client::port_status() {
        Ok(p) => p,
        Err(e) => return fail(b"port_status", e),
    };
    if ports.len() > cs.max_ports as usize {
        return fail_msg(b"port_status returned more entries than max_ports");
    }
    mark(b"port_status ok");

    mark(b"PASS");
}

fn mark(stage: &[u8]) {
    smoketest_log::mark(TAG, stage);
}

fn fail(stage: &[u8], err: DriverXhciError) {
    smoketest_log::fail_with_err(TAG, stage, err_name(err));
}

fn fail_msg(reason: &[u8]) {
    smoketest_log::fail_msg(TAG, reason);
}

fn fail_slot(err: SlotProofError) {
    match err {
        SlotProofError::Client(e) => fail(b"slot lifecycle", e),
        SlotProofError::InvalidSlot => fail_msg(b"enable_slot returned invalid slot id"),
        SlotProofError::CountDidNotIncrease => fail_msg(b"allocated slot count did not increase"),
        SlotProofError::CountDidNotReturn => {
            fail_msg(b"allocated slot count did not return to baseline")
        }
    }
}

fn err_name(e: DriverXhciError) -> &'static [u8] {
    match e {
        DriverXhciError::Dead => b"Dead",
        DriverXhciError::Stale => b"Stale",
        DriverXhciError::AccessDenied => b"AccessDenied",
        DriverXhciError::InvalidArgument => b"InvalidArgument",
        DriverXhciError::DeviceFailure => b"DeviceFailure",
        DriverXhciError::NoCallerPid => b"NoCallerPid",
        DriverXhciError::TransportFailure => b"TransportFailure",
        DriverXhciError::ProtocolMismatch => b"ProtocolMismatch",
        DriverXhciError::ShortReply => b"ShortReply",
    }
}
