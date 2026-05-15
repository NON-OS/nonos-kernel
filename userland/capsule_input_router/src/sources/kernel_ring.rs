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

use nonos_libc::{mk_input_event_drain, InputEvent};

// Kernel ring batch drain. The kernel surface registry MPSC ring is
// the single ingress: driver capsules call mk_input_event_post, this
// router calls mk_input_event_drain to pull a bounded batch each
// loop iteration. Normalisation is already done at post time, so
// the batch lands in this AS ready to route.

pub const MAX_BATCH: usize = 32;

pub fn drain_batch(scratch: &mut [InputEvent; MAX_BATCH]) -> usize {
    let rc = mk_input_event_drain(scratch.as_mut_ptr(), MAX_BATCH as u64);
    if rc <= 0 {
        return 0;
    }
    let n = rc as usize;
    if n > MAX_BATCH {
        MAX_BATCH
    } else {
        n
    }
}
