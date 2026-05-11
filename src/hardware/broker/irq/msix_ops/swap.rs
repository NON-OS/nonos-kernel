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

//! Test-mode `MsixOps` override. Production picks `RealMsixOps`
//! through `mod.rs`; this file only knows how to remember and
//! return whatever a test installed, without ever falling back to
//! real PCI primitives. A test that forgot to install ops and
//! reaches `current_ops()` gets an explicit panic instead of a
//! silent MMIO write.

use spin::Mutex;

use super::ops::MsixOps;

static OVERRIDE: Mutex<Option<&'static (dyn MsixOps + 'static)>> = Mutex::new(None);

pub fn current_ops() -> &'static dyn MsixOps {
    match *OVERRIDE.lock() {
        Some(ops) => ops,
        None => panic!("msix_ops: no test override installed; call install_ops_for_test first"),
    }
}

pub fn install_ops_for_test(ops: &'static dyn MsixOps) {
    *OVERRIDE.lock() = Some(ops);
}

pub fn clear_ops_for_test() {
    *OVERRIDE.lock() = None;
}
