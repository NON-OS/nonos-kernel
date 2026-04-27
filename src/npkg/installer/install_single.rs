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

use super::options::InstallOptions;
use crate::npkg::database::register_package;
use crate::npkg::download::{download_package, verify_checksum};
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::extract::{extract_package, PackageArchive};
use crate::npkg::hooks::{run_post_install, run_pre_install};
use crate::npkg::signature::verify_package;
use crate::npkg::types::{InstallReason, InstalledPackage, Package, PackageState};
use alloc::string::String;

pub(super) fn install_single_package(
    pkg: &Package,
    reason: InstallReason,
    options: &InstallOptions,
) -> NpkgResult<()> {
    crate::info!("npkg: installing {} {}", pkg.meta.name, pkg.meta.version.to_string());
    let archive_path = download_package(pkg)?;
    let archive_data = crate::fs::read_file_bytes(&archive_path)
        .map_err(|_| NpkgError::IoError(String::from("failed to read archive")))?;
    if !verify_checksum(&archive_data, &pkg.meta.checksum_blake3) {
        return Err(NpkgError::ChecksumMismatch(pkg.meta.name.clone()));
    }
    if let Some(ref sig_bytes) = pkg.meta.signature {
        let sig = crate::npkg::signature::PackageSignature {
            bytes: *sig_bytes,
            key_id: [0u8; 8],
            timestamp: 0,
        };
        verify_package(&archive_data, &sig)?;
    }
    if !options.no_scripts {
        if let Some(ref script) = pkg.install_script {
            run_pre_install(&pkg.meta.name, script)?;
        }
    }
    let archive = PackageArchive::open(&archive_data)?;
    let installed_files = extract_package(&archive, "/")?;
    let installed_pkg = InstalledPackage {
        meta: pkg.meta.clone(),
        install_time: crate::time::unix_timestamp(),
        install_reason: reason,
        files: installed_files,
        state: PackageState::Installed,
    };
    register_package(installed_pkg)?;
    let manifest = crate::npkg::manifest::Manifest::new(pkg.clone());
    let _ = crate::npkg::manifest::cache_manifest(&pkg.meta.name, &manifest);
    if !options.no_scripts {
        if let Some(ref script) = pkg.install_script {
            run_post_install(&pkg.meta.name, script)?;
        }
    }
    crate::info!("npkg: {} {} installed", pkg.meta.name, pkg.meta.version.to_string());
    Ok(())
}
