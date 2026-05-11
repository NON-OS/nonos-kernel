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

//! INTx with `flags == 0` and a healthy device record must still
//! work after the MSI-X plumbing landed. Verify the IO-APIC saw
//! the route and the grant came back at the bottom of the broker
//! pool.

use crate::arch::interrupt::broker::BROKER_VEC_MIN;
use crate::arch::interrupt::ioapic;
use crate::broker::irq::bind::bind;

use super::intx_setup::{fresh, intx_request, IRQ_LINE, PID};
use super::lock::TEST_LOCK;

#[test]
fn intx_path_unchanged() {
    let _g = TEST_LOCK.lock();
    let epoch = fresh();
    let r = bind(PID, intx_request(epoch)).expect("intx bind ok");
    assert_eq!(r.vector, BROKER_VEC_MIN);
    let routes = ioapic::recorded_routes();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].gsi, IRQ_LINE as u32);
    assert_eq!(routes[0].vector, BROKER_VEC_MIN);
}
