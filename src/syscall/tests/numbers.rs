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

use crate::syscall::abi::{tag4, REGISTRY};
use crate::syscall::numbers::SyscallNumber;
use crate::test::framework::TestResult;

pub(crate) fn test_active_numbers_round_trip() -> TestResult {
    for entry in REGISTRY {
        if entry.variant as u64 != entry.id {
            return TestResult::Fail;
        }
        if SyscallNumber::from_u64(entry.id) != Some(entry.variant) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_unassigned_numbers_return_none() -> TestResult {
    // Pre-NØNOS Linux numeric IDs and gaps between tag-encoded
    // groups. None should resolve through the registry.
    for n in &[0u64, 1, 9, 11, 60, 100, 600, 0x1050, 1207, 1310, u64::MAX] {
        if SyscallNumber::from_u64(*n).is_some() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_mk_debug_tag() -> TestResult {
    if SyscallNumber::MkDebug as u64 != tag4(b"MDBG") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
