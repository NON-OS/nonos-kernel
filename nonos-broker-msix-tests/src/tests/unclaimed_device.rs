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

//! Bind without a prior claim must be rejected before the kernel
//! ever consults the PCI side table — ownership comes first.

use crate::broker::irq::bind::bind;
use crate::broker::irq::types::IrqBindError;
use crate::fixtures::fake_msix_ops::FakeMsixOps;
use crate::fixtures::reset::reset_all;

use super::lock::TEST_LOCK;
use super::msix_setup::{msix_request, PID};

static FAKE: FakeMsixOps = FakeMsixOps::new();

#[test]
fn unclaimed_device_rejects() {
    let _g = TEST_LOCK.lock();
    reset_all();
    crate::broker::irq::msix_ops::install_ops_for_test(&FAKE);
    let err = bind(PID, msix_request(1, 4)).unwrap_err();
    assert_eq!(err, IrqBindError::NotClaimed);
}
