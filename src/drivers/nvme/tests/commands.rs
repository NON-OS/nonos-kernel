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

pub(crate) fn test_build_identify_command() -> TestResult {
    let cmd = types::SubmissionEntry::build_identify(0x10, 1, constants::CNS_NAMESPACE, 0x1000);

    if cmd.opcode() != constants::ADMIN_OPC_IDENTIFY {
        return TestResult::Fail;
    }
    if cmd.cid() != 0x10 {
        return TestResult::Fail;
    }
    if cmd.nsid != 1 {
        return TestResult::Fail;
    }
    if cmd.cdw10 != constants::CNS_NAMESPACE {
        return TestResult::Fail;
    }
    if cmd.prp1 != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_read_command() -> TestResult {
    let cmd = types::SubmissionEntry::build_read(0x20, 1, 0x1000, 8, 0x2000, 0x3000);

    if cmd.opcode() != constants::IO_OPC_READ {
        return TestResult::Fail;
    }
    if cmd.cid() != 0x20 {
        return TestResult::Fail;
    }
    if cmd.nsid != 1 {
        return TestResult::Fail;
    }
    if cmd.cdw10 != 0x1000 {
        return TestResult::Fail;
    }
    if cmd.cdw11 != 0 {
        return TestResult::Fail;
    }
    if cmd.cdw12 != 7 {
        return TestResult::Fail;
    }
    if cmd.prp1 != 0x2000 {
        return TestResult::Fail;
    }
    if cmd.prp2 != 0x3000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_write_command() -> TestResult {
    let cmd = types::SubmissionEntry::build_write(0x30, 1, 0x2000, 16, 0x4000, 0x5000);

    if cmd.opcode() != constants::IO_OPC_WRITE {
        return TestResult::Fail;
    }
    if cmd.cid() != 0x30 {
        return TestResult::Fail;
    }
    if cmd.nsid != 1 {
        return TestResult::Fail;
    }
    if cmd.cdw10 != 0x2000 {
        return TestResult::Fail;
    }
    if cmd.cdw12 != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_flush_command() -> TestResult {
    let cmd = types::SubmissionEntry::build_flush(0x40, 1);

    if cmd.opcode() != constants::IO_OPC_FLUSH {
        return TestResult::Fail;
    }
    if cmd.cid() != 0x40 {
        return TestResult::Fail;
    }
    if cmd.nsid != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_dsm_command() -> TestResult {
    let cmd = types::SubmissionEntry::build_dsm(0x50, 1, 4, constants::DSM_ATTR_DEALLOCATE, 0x6000);

    if cmd.opcode() != constants::IO_OPC_DSM {
        return TestResult::Fail;
    }
    if cmd.cid() != 0x50 {
        return TestResult::Fail;
    }
    if cmd.nsid != 1 {
        return TestResult::Fail;
    }
    if cmd.cdw10 != 3 {
        return TestResult::Fail;
    }
    if cmd.cdw11 != constants::DSM_ATTR_DEALLOCATE {
        return TestResult::Fail;
    }
    if cmd.prp1 != 0x6000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_create_cq_command() -> TestResult {
    let cmd = types::SubmissionEntry::build_create_cq(0x60, 1, 256, 0x7000, 0, true);

    if cmd.opcode() != constants::ADMIN_OPC_CREATE_CQ {
        return TestResult::Fail;
    }
    if cmd.cid() != 0x60 {
        return TestResult::Fail;
    }
    if cmd.cdw10 & 0xFFFF != 1 {
        return TestResult::Fail;
    }
    if (cmd.cdw10 >> 16) & 0xFFFF != 255 {
        return TestResult::Fail;
    }
    if cmd.prp1 != 0x7000 {
        return TestResult::Fail;
    }
    if cmd.cdw11 & 0x02 == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_build_create_sq_command() -> TestResult {
    let cmd = types::SubmissionEntry::build_create_sq(0x70, 1, 256, 0x8000, 1, 0);

    if cmd.opcode() != constants::ADMIN_OPC_CREATE_SQ {
        return TestResult::Fail;
    }
    if cmd.cid() != 0x70 {
        return TestResult::Fail;
    }
    if cmd.cdw10 & 0xFFFF != 1 {
        return TestResult::Fail;
    }
    if cmd.prp1 != 0x8000 {
        return TestResult::Fail;
    }
    if (cmd.cdw11 >> 16) & 0xFFFF != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
