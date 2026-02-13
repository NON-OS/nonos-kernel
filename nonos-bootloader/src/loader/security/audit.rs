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

use crate::loader::validate::ValidationContext;

#[derive(Debug)]
pub struct SecurityAudit {
    pub timestamp: u64,
    pub kernel_hash: [u8; 32],
    pub signature_verified: bool,
    pub policy_applied: &'static str,
    pub wx_warnings: usize,
    pub total_size: usize,
    pub segment_count: usize,
}

impl SecurityAudit {
    pub fn new(
        kernel_hash: [u8; 32],
        ctx: &ValidationContext,
        signature_verified: bool,
        policy_name: &'static str,
    ) -> Self {
        Self {
            timestamp: 0,
            kernel_hash,
            signature_verified,
            policy_applied: policy_name,
            wx_warnings: ctx.wx_segments,
            total_size: ctx.total_size,
            segment_count: ctx.segment_count,
        }
    }
}
