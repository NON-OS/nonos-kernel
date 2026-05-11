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

//! MSI-X is all-or-nothing per device per pid. A second `bind`
//! call on the same device while grants are live must be rejected
//! so the kernel never has to merge or re-program a partially
//! held MSI-X table.

use crate::broker::irq::bind::bind;
use crate::broker::irq::types::IrqBindError;
use crate::fixtures::fake_msix_ops::FakeMsixOps;

use super::lock::TEST_LOCK;
use super::msix_setup::{fresh, msix_request, PID};

static FAKE: FakeMsixOps = FakeMsixOps::new();

#[test]
fn second_bind_for_same_device_rejects() {
    let _g = TEST_LOCK.lock();
    let epoch = fresh(&FAKE);
    bind(PID, msix_request(epoch, 2)).expect("first bind ok");
    let err = bind(PID, msix_request(epoch, 1)).unwrap_err();
    assert_eq!(err, IrqBindError::AlreadyBound);
}
