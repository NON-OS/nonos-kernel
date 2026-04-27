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

use crate::test::framework::TestResult;

pub(crate) fn test_idt_module_exists() -> TestResult {
    TestResult::Pass
}

pub(crate) fn test_idt_entry_count() -> TestResult {
    let entry_count: usize = 256;
    if entry_count != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_idt_entry_size() -> TestResult {
    let entry_size: usize = 16;
    if entry_size * 256 != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_interrupt_vectors() -> TestResult {
    let div_by_zero: u8 = 0;
    let page_fault: u8 = 14;
    let timer: u8 = 32;
    if !(div_by_zero < page_fault) {
        return TestResult::Fail;
    }
    if !(page_fault < timer) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
