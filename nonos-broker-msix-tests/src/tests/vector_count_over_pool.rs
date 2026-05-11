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

use crate::arch::interrupt::broker::BROKER_VEC_COUNT;
use crate::broker::irq::bind::bind;
use crate::broker::irq::types::IrqBindError;
use crate::fixtures::fake_msix_ops::FakeMsixOps;

use super::lock::TEST_LOCK;
use super::msix_setup::{fresh, msix_request, PID};

static FAKE: FakeMsixOps = FakeMsixOps::new();

#[test]
fn vector_count_over_broker_pool_rejects() {
    let _g = TEST_LOCK.lock();
    let epoch = fresh(&FAKE);
    let count = (BROKER_VEC_COUNT + 1) as u32;
    let err = bind(PID, msix_request(epoch, count)).unwrap_err();
    assert_eq!(err, IrqBindError::BadVectorCount);
}
