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

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

pub const ED25519_SIG_SIZE: usize = 64;

pub struct SignedKernel {
    pub raw_bytes: Vec<u8>,
    pub kernel_bytes: Vec<u8>,
    pub signature: [u8; ED25519_SIG_SIZE],
}

pub fn load_signed_kernel(path: &Path) -> Result<SignedKernel> {
    let raw_bytes = fs::read(path)
        .with_context(|| format!("Failed to read signed kernel: {}", path.display()))?;

    if raw_bytes.len() < 128 {
        bail!("Signed kernel too small (must be at least 128 bytes)");
    }

    let sig_offset = raw_bytes.len() - ED25519_SIG_SIZE;
    let kernel_bytes = raw_bytes[..sig_offset].to_vec();

    let mut signature = [0u8; ED25519_SIG_SIZE];
    signature.copy_from_slice(&raw_bytes[sig_offset..]);

    Ok(SignedKernel { raw_bytes, kernel_bytes, signature })
}
