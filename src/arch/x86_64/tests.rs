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

use super::{IRQ_BASE, IST_DOUBLE_FAULT, IST_NMI, SEL_KERNEL_CODE, SEL_NULL};

#[test]
fn ist_constants() {
    assert!(IST_DOUBLE_FAULT > 0);
    assert!(IST_NMI > 0);
}

#[test]
fn segment_selectors() {
    assert_eq!(SEL_NULL, 0);
    assert!(SEL_KERNEL_CODE > 0);
}

#[test]
fn irq_base() {
    assert_eq!(IRQ_BASE, 32);
}
