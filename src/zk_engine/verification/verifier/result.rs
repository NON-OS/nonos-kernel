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

use crate::zk_engine::ZKError;

#[derive(Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub error: Option<ZKError>,
    pub timing_ms: u64,
    pub pairing_checks: u32,
}

impl VerificationResult {
    pub fn success(timing_ms: u64) -> Self {
        Self { valid: true, error: None, timing_ms, pairing_checks: 4 }
    }

    pub fn failure(error: ZKError, timing_ms: u64) -> Self {
        Self { valid: false, error: Some(error), timing_ms, pairing_checks: 0 }
    }
}
