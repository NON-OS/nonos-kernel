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
    nonos_id_cert_bytes: &[u8],
    capsule_name: &str,
) -> Result<(), ManifestVerifyError> {
    let cert_id = *blake3::hash(nonos_id_cert_bytes).as_bytes();
    let baseline_cert = boot_baseline::lookup(capsule_name).map(|b| b.cert);

    crate::sys::boot_log::info(&alloc::format!(
        "[verify:{}] cert ptr=0x{:x} len={} first16={:02x?}",
        capsule_name,
        nonos_id_cert_bytes.as_ptr() as u64,
        nonos_id_cert_bytes.len(),
        &nonos_id_cert_bytes[..nonos_id_cert_bytes.len().min(16)],
    ));
    crate::sys::boot_log::info(&alloc::format!(
        "[verify:{}] cert computed={} expected={} baseline={}",
        capsule_name,
        hex32(&cert_id),
        hex32(&manifest.nonos_id_cert_id),
        baseline_cert.as_ref().map(|h| hex32(h)).unwrap_or_else(|| alloc::string::String::from("UNKNOWN")),
    ));

    if cert_id != manifest.nonos_id_cert_id {
        let verdict = classify(&cert_id, &manifest.nonos_id_cert_id, baseline_cert.as_ref());
        crate::sys::boot_log::error(&alloc::format!(
            "[verify:{}] cert_id mismatch — verdict: {}",
            capsule_name, verdict,
        ));
        return Err(ManifestVerifyError::NonosIdCertIdMismatch);
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
            "H1/H2/H3: runtime corruption — baseline OK, live cert bytes diverged"
        }
        Some(b) if b != expected => {
            "setup: baseline cert never matched manifest.cert_id"
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
