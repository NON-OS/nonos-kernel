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

//! Host fixture for `crate::arch::interrupt::ioapic`. The bind
//! INTx path calls `program_route_external` and `mask`; both
//! record their arguments so tests can assert "this exact route
//! was programmed". Tests can flip `set_program_failure(true)` to
//! exercise the platform-error rollback in `bind_intx`.

use spin::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub gsi: u32,
    pub vector: u8,
    pub dest_apic_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskCall {
    pub gsi: u32,
    pub masked: bool,
}

static ROUTES: Mutex<alloc::vec::Vec<Route>> = Mutex::new(alloc::vec::Vec::new());
static MASKS: Mutex<alloc::vec::Vec<MaskCall>> = Mutex::new(alloc::vec::Vec::new());
static PROGRAM_FAILS: Mutex<bool> = Mutex::new(false);

pub fn program_route_external(gsi: u32, vector: u8, dest_apic_id: u32) -> Result<(), ()> {
    if *PROGRAM_FAILS.lock() {
        return Err(());
    }
    ROUTES.lock().push(Route { gsi, vector, dest_apic_id });
    Ok(())
}

pub fn mask(gsi: u32, masked: bool) -> Result<(), ()> {
    MASKS.lock().push(MaskCall { gsi, masked });
    Ok(())
}

pub fn recorded_routes() -> alloc::vec::Vec<Route> {
    ROUTES.lock().clone()
}

pub fn recorded_masks() -> alloc::vec::Vec<MaskCall> {
    MASKS.lock().clone()
}

pub fn set_program_failure(fail: bool) {
    *PROGRAM_FAILS.lock() = fail;
}

pub fn reset_for_test() {
    ROUTES.lock().clear();
    MASKS.lock().clear();
    *PROGRAM_FAILS.lock() = false;
}
