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

use crate::drivers::nvme::constants;
use crate::test::framework::TestResult;

pub(crate) fn test_constants() -> TestResult {
    if constants::PAGE_SIZE != 4096 {
        return TestResult::Fail;
    }
    if constants::ADMIN_QUEUE_DEPTH != 32 {
        return TestResult::Fail;
    }
    if constants::IO_QUEUE_DEPTH != 256 {
        return TestResult::Fail;
    }
    if constants::SUBMISSION_ENTRY_SIZE != 64 {
        return TestResult::Fail;
    }
    if constants::COMPLETION_ENTRY_SIZE != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_doorbell_calculation() -> TestResult {
    let dstrd = 0;
    let qid = 1;

    let sq_offset = constants::doorbell_sq_offset(dstrd, qid);
    let cq_offset = constants::doorbell_cq_offset(dstrd, qid);

    if sq_offset != 0x1000 + 8 {
        return TestResult::Fail;
    }
    if cq_offset != 0x1000 + 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_helpers() -> TestResult {
    let cap: u64 = 0x00200028_0002_01FF;

    if constants::cap_mqes(cap) != 0x01FF {
        return TestResult::Fail;
    }
    if constants::cap_dstrd(cap) != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aqa_encoding() -> TestResult {
    let aqa = constants::aqa(32, 32);
    if aqa & 0xFFF != 31 {
        return TestResult::Fail;
    }
    if (aqa >> 16) & 0xFFF != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_parsing() -> TestResult {
    if constants::version_major(0x00010400) != 1 {
        return TestResult::Fail;
    }
    if constants::version_minor(0x00010400) != 4 {
        return TestResult::Fail;
    }
    if constants::version_tertiary(0x00010400) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
