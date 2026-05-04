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

use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum SoftIrqType {
    Timer = 0,
    NetTx = 1,
    NetRx = 2,
    Block = 3,
    IrqPoll = 4,
    Tasklet = 5,
    Sched = 6,
    HrTimer = 7,
    Rcu = 8,
}

pub(super) static PENDING: AtomicU32 = AtomicU32::new(0);

pub(crate) fn raise_softirq(irq: SoftIrqType) {
    PENDING.fetch_or(1 << (irq as u8), Ordering::Release);
}

pub(crate) fn pending() -> bool {
    PENDING.load(Ordering::Acquire) != 0
}

pub(crate) fn get_pending() -> u32 {
    PENDING.load(Ordering::Acquire)
}
