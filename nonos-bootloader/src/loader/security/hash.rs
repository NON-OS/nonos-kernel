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

use crate::loader::errors::{LoaderError, LoaderResult};
use crate::log::logger::{log_error, log_info};

pub fn compute_kernel_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

pub fn verify_kernel_hash(data: &[u8], expected: &[u8; 32]) -> LoaderResult<()> {
    let computed = compute_kernel_hash(data);

    if &computed != expected {
        log_error("security", "SECURITY: Kernel hash mismatch");
        return Err(LoaderError::HashMismatch);
    }

    log_info("security", "Kernel hash verified");
    Ok(())
}
