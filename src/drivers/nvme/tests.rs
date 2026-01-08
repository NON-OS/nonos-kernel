// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
mod unit_tests {
    use super::super::*;
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

    #[test]
    fn test_controller_capabilities() {
        let cap: u64 = 0x00FF_0000_0020_00FF;
        let caps = types::ControllerCapabilities::from_register(cap);

        assert_eq!(caps.max_queue_entries, 256);
        assert!(caps.timeout_500ms_units > 0);
    }

    #[test]
    fn test_controller_version() {
        let vs: u32 = 0x0001_0400;
        let version = types::ControllerVersion::from_register(vs);

        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 4);
        assert_eq!(version.tertiary, 0);
        assert!(version.is_at_least(1, 3));
        assert!(version.is_at_least(1, 4));
        assert!(!version.is_at_least(1, 5));
    }

    #[test]
    fn test_lba_format() {
        let dword: u32 = 0x0000_0900;
        let format = types::LbaFormat::from_dword(dword);

        assert_eq!(format.lba_data_size_shift, 9);
        assert_eq!(format.lba_size(), 512);
        assert_eq!(format.metadata_size, 0);
    }

    #[test]
    fn test_lba_format_4k() {
        let dword: u32 = 0x0000_0C00;
        let format = types::LbaFormat::from_dword(dword);

        assert_eq!(format.lba_data_size_shift, 12);
        assert_eq!(format.lba_size(), 4096);
    }

    #[test]
    fn test_dsm_range() {
        let range = types::DsmRange::new(0x1000, 8, constants::DSM_ATTR_DEALLOCATE);

        assert_eq!(range.starting_lba, 0x1000);
        assert_eq!(range.lba_count, 8);
        assert_eq!(range.context_attributes, constants::DSM_ATTR_DEALLOCATE);
    }

    #[test]
    fn test_error_display() {
        let err = error::NvmeError::NoControllerFound;
        assert_eq!(err.as_str(), "No NVMe controller found on PCI bus");

        let err = error::NvmeError::CommandFailed { status_code: 0x281 };
        let s = alloc::format!("{}", err);
        assert!(s.contains("0x281"));
    }

    #[test]
    fn test_error_classification() {
        assert!(error::NvmeError::ControllerFatalStatus.is_fatal());
        assert!(error::NvmeError::CqCorruption.is_fatal());
        assert!(!error::NvmeError::CommandTimeout.is_fatal());

        assert!(error::NvmeError::CommandTimeout.is_recoverable());
        assert!(error::NvmeError::RateLimitExceeded.is_recoverable());
        assert!(!error::NvmeError::ControllerFatalStatus.is_recoverable());
    }

    #[test]
    fn test_status_code_parsing() {
        let status = error::NvmeStatusCode::from_status_field(0x0000);
        assert!(status.is_success());

        let status = error::NvmeStatusCode::from_status_field(0x0002);
        assert_eq!(status, error::NvmeStatusCode::InvalidOpcode);

        let status = error::NvmeStatusCode::from_status_field(0x0004);
        assert_eq!(status, error::NvmeStatusCode::InvalidField);
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::PAGE_SIZE, 4096);
        assert_eq!(constants::ADMIN_QUEUE_DEPTH, 32);
        assert_eq!(constants::IO_QUEUE_DEPTH, 256);
        assert_eq!(constants::SUBMISSION_ENTRY_SIZE, 64);
        assert_eq!(constants::COMPLETION_ENTRY_SIZE, 16);
    }

    #[test]
    fn test_doorbell_calculation() {
        let dstrd = 0;
        let qid = 1;

        let sq_offset = constants::doorbell_sq_offset(dstrd, qid);
        let cq_offset = constants::doorbell_cq_offset(dstrd, qid);

        assert_eq!(sq_offset, 0x1000 + 8);
        assert_eq!(cq_offset, 0x1000 + 12);
    }

    #[test]
    fn test_cap_helpers() {
        let cap: u64 = 0x00200028_0002_01FF;

        assert_eq!(constants::cap_mqes(cap), 0x01FF);
        assert_eq!(constants::cap_dstrd(cap), 0);
    }

    #[test]
    fn test_aqa_encoding() {
        let aqa = constants::aqa(32, 32);
        assert_eq!(aqa & 0xFFF, 31);
        assert_eq!((aqa >> 16) & 0xFFF, 31);
    }

    #[test]
    fn test_version_parsing() {
        assert_eq!(constants::version_major(0x00010400), 1);
        assert_eq!(constants::version_minor(0x00010400), 4);
        assert_eq!(constants::version_tertiary(0x00010400), 0);
    }

    #[test]
    fn test_stats_atomic_operations() {
        let stats = stats::NvmeStats::new();

        stats.record_submit();
        stats.record_submit();
        stats.record_complete();
        stats.record_read(4096);
        stats.record_write(8192);
        stats.record_error();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.commands_submitted, 2);
        assert_eq!(snapshot.commands_completed, 1);
        assert_eq!(snapshot.read_commands, 1);
        assert_eq!(snapshot.write_commands, 1);
        assert_eq!(snapshot.bytes_read, 4096);
        assert_eq!(snapshot.bytes_written, 8192);
        assert_eq!(snapshot.errors, 1);
    }

    #[test]
    fn test_security_stats() {
        let stats = stats::SecurityStats::new();

        stats.record_rate_limit();
        stats.record_lba_validation_failure();
        stats.record_dma_validation_failure();
        stats.record_cq_corruption();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rate_limit_hits, 1);
        assert_eq!(snapshot.lba_validation_failures, 1);
        assert_eq!(snapshot.dma_validation_failures, 1);
        assert_eq!(snapshot.cq_corruption_events, 1);
        assert!(snapshot.has_critical_events());
    }

    #[test]
    fn test_namespace_lba_validation() {
        let mut ns_data = [0u8; 4096];

        ns_data[0x00..0x08].copy_from_slice(&1000u64.to_le_bytes());
        ns_data[0x08..0x10].copy_from_slice(&1000u64.to_le_bytes());
        ns_data[0x19] = 0;
        ns_data[0x1A] = 0;
        ns_data[0x80..0x84].copy_from_slice(&0x0000_0900u32.to_le_bytes());

        let ns = namespace::Namespace::from_identify_data(1, &ns_data).unwrap();

        assert!(ns.validate_lba_range(0, 100).is_ok());
        assert!(ns.validate_lba_range(900, 100).is_ok());
        assert!(ns.validate_lba_range(900, 101).is_err());
        assert!(ns.validate_lba_range(1000, 1).is_err());
        assert!(ns.validate_lba_range(0, 0).is_err());
    }

    #[test]
    fn test_namespace_manager() {
        let mut manager = namespace::NamespaceManager::new();

        let mut ns_data = [0u8; 4096];
        ns_data[0x00..0x08].copy_from_slice(&1000u64.to_le_bytes());
        ns_data[0x08..0x10].copy_from_slice(&1000u64.to_le_bytes());
        ns_data[0x80..0x84].copy_from_slice(&0x0000_0900u32.to_le_bytes());

        let ns1 = namespace::Namespace::from_identify_data(1, &ns_data).unwrap();
        let ns2 = namespace::Namespace::from_identify_data(2, &ns_data).unwrap();

        manager.add(ns1);
        manager.add(ns2);

        assert_eq!(manager.count(), 2);
        assert!(manager.get(1).is_some());
        assert!(manager.get(2).is_some());
        assert!(manager.get(3).is_none());

        let nsids = manager.nsids();
        assert_eq!(nsids, vec![1, 2]);
    }

    #[test]
    fn test_namespace_list_parsing() {
        let mut data = [0u8; 4096];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..8].copy_from_slice(&2u32.to_le_bytes());
        data[8..12].copy_from_slice(&5u32.to_le_bytes());

        let nsids = namespace::parse_namespace_list(&data);
        assert_eq!(nsids, vec![1, 2, 5]);
    }

    #[test]
    fn test_build_identify_command() {
        let cmd = types::SubmissionEntry::build_identify(0x10, 1, constants::CNS_NAMESPACE, 0x1000);

        assert_eq!(cmd.opcode(), constants::ADMIN_OPC_IDENTIFY);
        assert_eq!(cmd.cid(), 0x10);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, constants::CNS_NAMESPACE);
        assert_eq!(cmd.prp1, 0x1000);
    }

    #[test]
    fn test_build_read_command() {
        let cmd = types::SubmissionEntry::build_read(
            0x20,
            1,
            0x1000,
            8,
            0x2000,
            0x3000,
        );

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
        let cmd = types::SubmissionEntry::build_write(
            0x30,
            1,
            0x2000,
            16,
            0x4000,
            0x5000,
        );

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
        let cmd = types::SubmissionEntry::build_dsm(
            0x50,
            1,
            4,
            constants::DSM_ATTR_DEALLOCATE,
            0x6000,
        );

        assert_eq!(cmd.opcode(), constants::IO_OPC_DSM);
        assert_eq!(cmd.cid(), 0x50);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 3);
        assert_eq!(cmd.cdw11, constants::DSM_ATTR_DEALLOCATE);
        assert_eq!(cmd.prp1, 0x6000);
    }

    #[test]
    fn test_build_create_cq_command() {
        let cmd = types::SubmissionEntry::build_create_cq(
            0x60,
            1,
            256,
            0x7000,
            0,
            true,
        );

        assert_eq!(cmd.opcode(), constants::ADMIN_OPC_CREATE_CQ);
        assert_eq!(cmd.cid(), 0x60);
        assert_eq!(cmd.cdw10 & 0xFFFF, 1);
        assert_eq!((cmd.cdw10 >> 16) & 0xFFFF, 255);
        assert_eq!(cmd.prp1, 0x7000);
        assert!(cmd.cdw11 & 0x02 != 0);
    }

    #[test]
    fn test_build_create_sq_command() {
        let cmd = types::SubmissionEntry::build_create_sq(
            0x70,
            1,
            256,
            0x8000,
            1,
            0,
        );

        assert_eq!(cmd.opcode(), constants::ADMIN_OPC_CREATE_SQ);
        assert_eq!(cmd.cid(), 0x70);
        assert_eq!(cmd.cdw10 & 0xFFFF, 1);
        assert_eq!(cmd.prp1, 0x8000);
        assert_eq!((cmd.cdw11 >> 16) & 0xFFFF, 1);
    }
}
