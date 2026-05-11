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

//! A capsule that quoted an old epoch must get `StaleEpoch` even
//! when it owns the (current) claim. Each successful re-claim bumps
//! the epoch, so a leftover epoch from a prior generation is the
//! signal that the capsule's view of the device is out of date.

use crate::broker::claim;
use crate::broker::pci::ownership::resolve;
use crate::broker::pci::types::{PciWriteError, PciWriteRequest};
use crate::fixtures::reset::reset_all;

use super::lock::TEST_LOCK;

const PID: u32 = 33;
const DEVICE_ID: u64 = 64;

#[test]
fn stale_claim_epoch_rejects() {
    let _g = TEST_LOCK.lock();
    reset_all();
    let epoch = claim::install_for_test(PID, DEVICE_ID);
    let req =
        PciWriteRequest { device_id: DEVICE_ID, claim_epoch: epoch + 1, offset: 0x04, value: 0 };
    let err = resolve(PID, &req).unwrap_err();
    assert_eq!(err, PciWriteError::StaleEpoch);
}
