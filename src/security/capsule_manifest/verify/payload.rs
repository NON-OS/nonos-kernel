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

extern crate alloc;

use super::super::boot_baseline;
use super::super::error::ManifestVerifyError;
use super::super::schema::CapsuleManifest;

pub(super) fn check(
    manifest: &CapsuleManifest,
    payload: &[u8],
    capsule_name: &str,
) -> Result<(), ManifestVerifyError> {
    let computed = *blake3::hash(payload).as_bytes();
    let baseline_elf = boot_baseline::lookup(capsule_name).map(|b| b.elf);

    crate::sys::boot_log::info(&alloc::format!(
        "[verify:{}] elf ptr=0x{:x} len={} first16={:02x?}",
        capsule_name,
        payload.as_ptr() as u64,
        payload.len(),
        &payload[..payload.len().min(16)],
    ));
    crate::sys::boot_log::info(&alloc::format!(
        "[verify:{}] elf computed={} expected={} baseline={}",
        capsule_name,
        hex32(&computed),
        hex32(&manifest.payload_hash),
        baseline_elf.as_ref().map(|h| hex32(h)).unwrap_or_else(|| alloc::string::String::from("UNKNOWN")),
    ));

    if computed != manifest.payload_hash {
        let verdict = classify(&computed, &manifest.payload_hash, baseline_elf.as_ref());
        crate::sys::boot_log::error(&alloc::format!(
            "[verify:{}] payload mismatch — verdict: {}",
            capsule_name, verdict,
        ));
        return Err(ManifestVerifyError::PayloadHashMismatch);
    }
    Ok(())
}

fn classify(
    computed: &[u8; 32],
    expected: &[u8; 32],
    baseline: Option<&[u8; 32]>,
) -> &'static str {
    match baseline {
        None => "no-baseline (boot_baseline missing this capsule)",
        Some(b) if b == expected && b == computed => {
            "H5: bytes match baseline AND manifest BUT != check — comparison-code bug"
        }
        Some(b) if b == expected && b != computed => {
            "H1/H2/H3: runtime corruption — baseline OK, live ELF bytes diverged"
        }
        Some(b) if b != expected => {
            "setup: baseline never matched manifest — embed/sign path drift"
        }
        Some(_) => "unclassified",
    }
}

fn hex32(bytes: &[u8; 32]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(64);
    for b in bytes {
        s.push_str(&alloc::format!("{:02x}", b));
    }
    s
}
