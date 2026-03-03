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
    use crate::drivers::nvme::stats;

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
}
