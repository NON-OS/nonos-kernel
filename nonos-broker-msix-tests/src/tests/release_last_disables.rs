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

//! Releasing the last MSI-X grant for a device must clear the
//! device-side MSI-X enable bit so the next bind starts from a
//! clean post-reset state. The fake programmer records the
//! disable call by PCI address.

use crate::broker::irq::bind::bind;
use crate::broker::irq::release::unmap_grant;
use crate::fixtures::fake_msix_ops::FakeMsixOps;

use super::lock::TEST_LOCK;
use super::msix_setup::{address, fresh, msix_request, PID};

static FAKE: FakeMsixOps = FakeMsixOps::new();

#[test]
fn releasing_last_disables_msix() {
    let _g = TEST_LOCK.lock();
    let epoch = fresh(&FAKE);
    let r = bind(PID, msix_request(epoch, 2)).expect("bind ok");
    unmap_grant(PID, r.grant_id).expect("first release");
    unmap_grant(PID, r.grant_id + 1).expect("second release");
    let disables = FAKE.disables.lock().clone();
    assert_eq!(disables, alloc::vec![address()]);
}
