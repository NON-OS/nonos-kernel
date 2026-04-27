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

use crate::drivers::nvme::{constants, types};
use crate::test::framework::TestResult;

pub(crate) fn test_submission_entry_creation() -> TestResult {
    let entry = types::SubmissionEntry::new();
    if entry.opcode() != 0 {
        return TestResult::Fail;
    }
    if entry.cid() != 0 {
        return TestResult::Fail;
    }
    if entry.nsid != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_submission_entry_opcode_cid() -> TestResult {
    let mut entry = types::SubmissionEntry::new();
    entry.set_opcode(0x02);
    entry.set_cid(0x1234);

    if entry.opcode() != 0x02 {
        return TestResult::Fail;
    }
    if entry.cid() != 0x1234 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_submission_entry_sanitize() -> TestResult {
    let mut entry = types::SubmissionEntry::new();
    entry.set_opcode(constants::IO_OPC_READ);
    entry.cdw2 = 0xDEADBEEF;
    entry.cdw3 = 0xCAFEBABE;
    entry.cdw0 |= 0xFF00;

    entry.sanitize();

    if entry.cdw2 != 0 {
        return TestResult::Fail;
    }
    if entry.cdw3 != 0 {
        return TestResult::Fail;
    }
    if entry.cdw0 & 0x3C00 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completion_entry_status() -> TestResult {
    let entry =
        types::CompletionEntry { dw0: 0, dw1: 0, sq_head: 0, sq_id: 0, cid: 0, status: 0x0001 };

    if !entry.phase() {
        return TestResult::Fail;
    }
    if !entry.is_success() {
        return TestResult::Fail;
    }
    if entry.is_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_completion_entry_error() -> TestResult {
    let entry =
        types::CompletionEntry { dw0: 0, dw1: 0, sq_head: 0, sq_id: 0, cid: 0, status: 0x0005 };

    if !entry.phase() {
        return TestResult::Fail;
    }
    if entry.is_success() {
        return TestResult::Fail;
    }
    if !entry.is_error() {
        return TestResult::Fail;
    }
    if entry.status_code() != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
