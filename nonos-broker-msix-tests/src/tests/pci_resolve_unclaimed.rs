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

//! Two flavours of `NotClaimed`. The first reaches the kernel
//! without any matching claim; the second does have a claim, but
//! the caller pid is not the holder.

use crate::broker::claim;
use crate::broker::pci::ownership::resolve;
use crate::broker::pci::types::{PciWriteError, PciWriteRequest};
use crate::fixtures::reset::reset_all;

use super::lock::TEST_LOCK;

const HOLDER_PID: u32 = 21;
const INTRUDER_PID: u32 = 22;
const DEVICE_ID: u64 = 42;

#[test]
fn no_claim_at_all_rejects() {
    let _g = TEST_LOCK.lock();
    reset_all();
    let req = PciWriteRequest { device_id: DEVICE_ID, claim_epoch: 1, offset: 0x04, value: 0 };
    let err = resolve(HOLDER_PID, &req).unwrap_err();
    assert_eq!(err, PciWriteError::NotClaimed);
}

#[test]
fn claim_held_by_different_pid_rejects() {
    let _g = TEST_LOCK.lock();
    reset_all();
    let epoch = claim::install_for_test(HOLDER_PID, DEVICE_ID);
    let req =
        PciWriteRequest { device_id: DEVICE_ID, claim_epoch: epoch, offset: 0x04, value: 0 };
    let err = resolve(INTRUDER_PID, &req).unwrap_err();
    assert_eq!(err, PciWriteError::NotClaimed);
}
