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
    fn test_submission_entry_creation() {
        let entry = types::SubmissionEntry::new();
        assert_eq!(entry.opcode(), 0);
        assert_eq!(entry.cid(), 0);
        assert_eq!(entry.nsid, 0);
    }

    #[test]
    fn test_submission_entry_opcode_cid() {
        let mut entry = types::SubmissionEntry::new();
        entry.set_opcode(0x02);
        entry.set_cid(0x1234);

        assert_eq!(entry.opcode(), 0x02);
        assert_eq!(entry.cid(), 0x1234);
    }

    #[test]
    fn test_submission_entry_sanitize() {
        let mut entry = types::SubmissionEntry::new();
        entry.set_opcode(constants::IO_OPC_READ);
        entry.cdw2 = 0xDEADBEEF;
        entry.cdw3 = 0xCAFEBABE;
        entry.cdw0 |= 0xFF00;

        entry.sanitize();

        assert_eq!(entry.cdw2, 0);
        assert_eq!(entry.cdw3, 0);
        assert_eq!(entry.cdw0 & 0xFC00, 0);
    }

    #[test]
    fn test_completion_entry_status() {
        let entry = types::CompletionEntry {
            dw0: 0,
            dw1: 0,
            sq_head: 0,
            sq_id: 0,
            cid: 0,
            status: 0x0001,
        };

        assert!(entry.phase());
        assert!(entry.is_success());
        assert!(!entry.is_error());
    }

    #[test]
    fn test_completion_entry_error() {
        let entry = types::CompletionEntry {
            dw0: 0,
            dw1: 0,
            sq_head: 0,
            sq_id: 0,
            cid: 0,
            status: 0x0005,
        };

        assert!(entry.phase());
        assert!(!entry.is_success());
        assert!(entry.is_error());
        assert_eq!(entry.status_code(), 0x02);
    }
}
