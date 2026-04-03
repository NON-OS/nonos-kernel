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

use super::super::stats::SecurityStatsSnapshot;

#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    pub nsid: u32,
    pub block_count: u64,
    pub block_size: u32,
    pub capacity_bytes: u64,
}

#[derive(Default, Clone)]
pub struct NvmeSecurityStats {
    pub timeouts: u64,
    pub rate_limit_hits: u64,
    pub lba_validation_failures: u64,
    pub dma_validation_failures: u64,
    pub cid_mismatches: u64,
    pub phase_errors: u64,
    pub command_errors: u64,
    pub namespace_errors: u64,
}

impl From<SecurityStatsSnapshot> for NvmeSecurityStats {
    fn from(s: SecurityStatsSnapshot) -> Self {
        Self {
            timeouts: 0,
            rate_limit_hits: s.rate_limit_hits,
            lba_validation_failures: s.lba_validation_failures,
            dma_validation_failures: s.dma_validation_failures,
            cid_mismatches: s.cid_mismatches,
            phase_errors: s.phase_errors,
            command_errors: s.command_errors,
            namespace_errors: s.namespace_errors,
        }
    }
}
