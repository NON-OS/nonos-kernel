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

use crate::arch::interrupt::ioapic;
use crate::broker::claim;
use crate::broker::irq::msix_ops;
use crate::broker::irq::{records, slots};
use crate::broker::pci_index;
use crate::broker::table;

pub fn reset_all() {
    claim::reset_for_test();
    pci_index::install(alloc::vec::Vec::new());
    table::reset_for_test();
    slots::reset_for_test();
    records::reset_for_test();
    ioapic::reset_for_test();
    msix_ops::clear_ops_for_test();
}
