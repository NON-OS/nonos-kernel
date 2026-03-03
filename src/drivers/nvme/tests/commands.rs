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

#[cfg(test)]
mod tests {
    use crate::drivers::nvme::{constants, types};

    #[test]
    fn test_build_identify_command() {
        let cmd =
            types::SubmissionEntry::build_identify(0x10, 1, constants::CNS_NAMESPACE, 0x1000);

        assert_eq!(cmd.opcode(), constants::ADMIN_OPC_IDENTIFY);
        assert_eq!(cmd.cid(), 0x10);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, constants::CNS_NAMESPACE);
        assert_eq!(cmd.prp1, 0x1000);
    }

    #[test]
    fn test_build_read_command() {
        let cmd = types::SubmissionEntry::build_read(0x20, 1, 0x1000, 8, 0x2000, 0x3000);

        assert_eq!(cmd.opcode(), constants::IO_OPC_READ);
        assert_eq!(cmd.cid(), 0x20);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 0x1000);
        assert_eq!(cmd.cdw11, 0);
        assert_eq!(cmd.cdw12, 7);
        assert_eq!(cmd.prp1, 0x2000);
        assert_eq!(cmd.prp2, 0x3000);
    }

    #[test]
    fn test_build_write_command() {
        let cmd = types::SubmissionEntry::build_write(0x30, 1, 0x2000, 16, 0x4000, 0x5000);

        assert_eq!(cmd.opcode(), constants::IO_OPC_WRITE);
        assert_eq!(cmd.cid(), 0x30);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 0x2000);
        assert_eq!(cmd.cdw12, 15);
    }

    #[test]
    fn test_build_flush_command() {
        let cmd = types::SubmissionEntry::build_flush(0x40, 1);

        assert_eq!(cmd.opcode(), constants::IO_OPC_FLUSH);
        assert_eq!(cmd.cid(), 0x40);
        assert_eq!(cmd.nsid, 1);
    }

    #[test]
    fn test_build_dsm_command() {
        let cmd =
            types::SubmissionEntry::build_dsm(0x50, 1, 4, constants::DSM_ATTR_DEALLOCATE, 0x6000);

        assert_eq!(cmd.opcode(), constants::IO_OPC_DSM);
        assert_eq!(cmd.cid(), 0x50);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 3);
        assert_eq!(cmd.cdw11, constants::DSM_ATTR_DEALLOCATE);
        assert_eq!(cmd.prp1, 0x6000);
    }

    #[test]
    fn test_build_create_cq_command() {
        let cmd = types::SubmissionEntry::build_create_cq(0x60, 1, 256, 0x7000, 0, true);

        assert_eq!(cmd.opcode(), constants::ADMIN_OPC_CREATE_CQ);
        assert_eq!(cmd.cid(), 0x60);
        assert_eq!(cmd.cdw10 & 0xFFFF, 1);
        assert_eq!((cmd.cdw10 >> 16) & 0xFFFF, 255);
        assert_eq!(cmd.prp1, 0x7000);
        assert!(cmd.cdw11 & 0x02 != 0);
    }

    #[test]
    fn test_build_create_sq_command() {
        let cmd = types::SubmissionEntry::build_create_sq(0x70, 1, 256, 0x8000, 1, 0);

        assert_eq!(cmd.opcode(), constants::ADMIN_OPC_CREATE_SQ);
        assert_eq!(cmd.cid(), 0x70);
        assert_eq!(cmd.cdw10 & 0xFFFF, 1);
        assert_eq!(cmd.prp1, 0x8000);
        assert_eq!((cmd.cdw11 >> 16) & 0xFFFF, 1);
    }
}
