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

//! Canonical bytes a publisher signs for one release. Publisher
//! authority covers artifact identity and requested authority.
//! Marketplace validation is signed by the enclosing operator index.

extern crate alloc;

use alloc::vec::Vec;

use super::writer::Writer;
use crate::types::CapsuleRelease;

const RELEASE_SIGNING_DOMAIN: &[u8] = b"NONOS.marketplace.release.v1";

pub fn release_signing_bytes(release: &CapsuleRelease) -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = Writer::new(&mut out);
    w.lp_bytes(RELEASE_SIGNING_DOMAIN);
    w.lp_string(&release.release_id);
    w.fixed(&release.manifest_hash);
    w.fixed(&release.package_hash);
    w.lp_string(&release.package_url);

    w.u32(release.supported_arches.len() as u32);
    for arch in &release.supported_arches {
        w.lp_string(arch);
    }

    w.u32(release.kernel_abi_min);
    w.u32(release.required_capabilities.len() as u32);
    for cap in &release.required_capabilities {
        w.lp_string(cap);
    }
    out
}
