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

//! When the programmer fails mid-run, the bind path must release
//! the broker slots it reserved and insert no records. The next
//! call into `try_alloc_contiguous` should hand back the same
//! base slot, proving the bitmap was actually cleared.

use crate::arch::interrupt::broker::BROKER_VEC_COUNT;
use crate::broker::irq::bind::bind;
use crate::broker::irq::slots;
use crate::broker::irq::types::IrqBindError;
use crate::fixtures::fake_msix_ops::FakeMsixOps;

use super::lock::TEST_LOCK;
use super::msix_setup::{fresh, msix_request, PID};

static FAKE: FakeMsixOps = FakeMsixOps::new();

#[test]
fn programmer_failure_rolls_back_slots() {
    let _g = TEST_LOCK.lock();
    let epoch = fresh(&FAKE);
    *FAKE.program_should_fail.lock() = true;
    let err = bind(PID, msix_request(epoch, 4)).unwrap_err();
    assert_eq!(err, IrqBindError::MsixProgramFailed);
    let after = slots::try_alloc_contiguous(BROKER_VEC_COUNT).expect("pool fully restored");
    assert_eq!(after, 0);
}
