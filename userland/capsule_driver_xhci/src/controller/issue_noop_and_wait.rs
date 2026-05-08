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

// P0 round trip: enqueue No-op, kick host doorbell, poll event
// ring for the matching Command Completion Event, verify
// CC_SUCCESS. Caller guarantees the controller is running; the
// service loop's IRQ consumer takes over after this returns.

use super::ring_doorbell::ring_doorbell;
use crate::constants::{CC_SUCCESS, TRB_TYPE_CMD_COMPLETION_EVENT};
use crate::error::{XhciError, XhciResult};
use crate::regs::runtime::erdp_program;
use crate::rings::command::CommandRing;
use crate::rings::event::EventRing;
use crate::trb::commands::noop_command;

const COMPLETION_POLL_LIMIT: u32 = 1_000_000;

pub fn issue_noop_and_wait(
    op_doorbell_base: u64,
    intr_base: u64,
    cmd_ring: &mut CommandRing,
    evt_ring: &mut EventRing,
) -> XhciResult<()> {
    let trb = noop_command(cmd_ring.cycle() != 0);
    let issued_phys = cmd_ring.enqueue(trb)?;
    ring_doorbell(op_doorbell_base, 0, 0);

    for _ in 0..COMPLETION_POLL_LIMIT {
        if evt_ring.has_event() {
            let event = evt_ring.current_trb();
            evt_ring.advance();
            erdp_program(intr_base, evt_ring.current_dequeue_phys(), true, 0);

            if event.get_type() != TRB_TYPE_CMD_COMPLETION_EVENT {
                continue;
            }
            if event.get_pointer() & !0xF != issued_phys & !0xF {
                continue;
            }
            let cc = event.completion_code();
            if cc != CC_SUCCESS {
                return Err(XhciError::CommandCompletionFailed(cc));
            }
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(XhciError::CommandCompletionTimeout)
}
