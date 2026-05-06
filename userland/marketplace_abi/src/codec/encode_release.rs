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

use super::encode_validation;
use super::writer::Writer;
use crate::types::CapsuleRelease;

pub(super) fn write(w: &mut Writer<'_>, release: &CapsuleRelease) {
    w.lp_string(&release.release_id);
    w.fixed(&release.manifest_hash);
    w.fixed(&release.package_hash);
    w.lp_string(&release.package_url);
    w.lp_bytes(&release.publisher_signature);

    w.u32(release.supported_arches.len() as u32);
    for arch in &release.supported_arches {
        w.lp_string(arch);
    }

    w.u32(release.kernel_abi_min);

    w.u32(release.required_capabilities.len() as u32);
    for cap in &release.required_capabilities {
        w.lp_string(cap);
    }

    encode_validation::write(w, &release.validation);
}
