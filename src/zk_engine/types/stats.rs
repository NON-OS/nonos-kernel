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

use core::sync::atomic::{AtomicU32, AtomicU64};

#[derive(Debug)]
pub struct ZKStats {
    pub proofs_generated: AtomicU64,
    pub proofs_verified: AtomicU64,
    pub verification_failures: AtomicU64,
    pub circuits_compiled: AtomicU32,
    pub total_proving_time_ms: AtomicU64,
    pub total_verification_time_ms: AtomicU64,
}
