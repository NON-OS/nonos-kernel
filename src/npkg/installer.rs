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

use alloc::string::String;
use alloc::vec::Vec;
use super::types::{
    Package, InstalledPackage, PackageState, InstallReason,
};
use super::database::{register_package, unregister_package, query_by_name, is_installed};
use super::download::{download_package, verify_checksum};
use super::extract::{extract_package, PackageArchive};
use super::hooks::{run_pre_install, run_post_install, run_pre_remove, run_post_remove};
use super::resolver::{resolve_dependencies, check_conflicts, ResolutionResult};
use super::signature::verify_package;
use super::error::{NpkgError, NpkgResult};

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub force: bool,
    pub no_deps: bool,
    pub no_scripts: bool,
    pub download_only: bool,
    pub as_dependency: bool,
    pub reinstall: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            force: false,
            no_deps: false,
            no_scripts: false,
            download_only: false,
            as_dependency: false,
            reinstall: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RemoveOptions {
    pub recursive: bool,
    pub no_scripts: bool,
    pub keep_config: bool,
    pub purge: bool,
}

impl Default for RemoveOptions {
    fn default() -> Self {
        Self {
            recursive: false,
            no_scripts: false,
            keep_config: true,
            purge: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpgradeOptions {
    pub no_deps: bool,
    pub no_scripts: bool,
    pub download_only: bool,
}

impl Default for UpgradeOptions {
    fn default() -> Self {
        Self {
            no_deps: false,
            no_scripts: false,
            download_only: false,
        }
    }
}

pub fn install_package(name: &str, options: &InstallOptions) -> NpkgResult<()> {
    install_packages(&[name], options)
}

pub fn install_packages(names: &[&str], options: &InstallOptions) -> NpkgResult<()> {
    if !options.reinstall {
        for name in names {
            if is_installed(name) && !options.force {
                return Err(NpkgError::AlreadyInstalled(String::from(*name)));
            }
        }
    }

    let resolution = if options.no_deps {
        let mut result = ResolutionResult {
            to_install: Vec::new(),
            to_upgrade: Vec::new(),
            to_remove: Vec::new(),
            satisfied: Vec::new(),
            optional: Vec::new(),
        };

        for name in names {
            let pkg = super::repository::find_package(name)
                .ok_or_else(|| NpkgError::PackageNotFound(String::from(*name)))?;

            let reason = if options.as_dependency {
                InstallReason::Dependency
            } else {
                InstallReason::Explicit
            };

            result.to_install.push((pkg, reason));
        }

        result
    } else {
        resolve_dependencies(names)?
    };

    let packages: Vec<&Package> = resolution.to_install.iter().map(|(p, _)| p).collect();
    check_conflicts(&packages)?;

    if options.download_only {
        for (pkg, _) in &resolution.to_install {
            let _ = download_package(pkg)?;
        }
        return Ok(());
    }

    for name in &resolution.to_remove {
        remove_package(name, &RemoveOptions::default())?;
    }

    for (pkg, reason) in resolution.to_install {
        install_single_package(&pkg, reason, options)?;
    }

    for (pkg, _old_version) in resolution.to_upgrade {
        let reason = query_by_name(&pkg.meta.name)
            .map(|p| p.install_reason)
            .unwrap_or(InstallReason::Explicit);

        install_single_package(&pkg, reason, options)?;
    }

    Ok(())
}

fn install_single_package(
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
        let sig = super::signature::PackageSignature {
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

    let manifest = super::manifest::Manifest::new(pkg.clone());
    let _ = super::manifest::cache_manifest(&pkg.meta.name, &manifest);

    if !options.no_scripts {
        if let Some(ref script) = pkg.install_script {
            run_post_install(&pkg.meta.name, script)?;
        }
    }

    crate::info!("npkg: {} {} installed", pkg.meta.name, pkg.meta.version.to_string());
    Ok(())
}

pub fn remove_package(name: &str, options: &RemoveOptions) -> NpkgResult<()> {
    remove_packages(&[name], options)
}

pub fn remove_packages(names: &[&str], options: &RemoveOptions) -> NpkgResult<()> {
    for name in names {
        if !is_installed(name) {
            return Err(NpkgError::NotInstalled(String::from(*name)));
        }
    }

    if options.recursive {
        let mut to_remove: Vec<String> = names.iter().map(|s| String::from(*s)).collect();
        let orphans = super::database::get_orphans();
        for orphan in orphans {
            if !to_remove.contains(&orphan) {
                to_remove.push(orphan);
            }
        }

        for name in &to_remove {
            remove_single_package(name, options)?;
        }
    } else {
        for name in names {
            remove_single_package(name, options)?;
        }
    }

    Ok(())
}

fn remove_single_package(name: &str, options: &RemoveOptions) -> NpkgResult<()> {
    let pkg = query_by_name(name)
        .ok_or_else(|| NpkgError::NotInstalled(String::from(name)))?;

    crate::info!("npkg: removing {} {}", pkg.meta.name, pkg.meta.version.to_string());

    if !options.no_scripts {
        run_pre_remove(name, "")?;
    }

    for file in pkg.files.iter().rev() {
        if options.keep_config && is_config_file(file) {
            continue;
        }

        if crate::fs::is_directory(file) {
            let _ = crate::fs::rmdir(file);
        } else {
            let _ = crate::fs::unlink(file);
        }
    }

    if options.purge {
        let config_dir = alloc::format!("/etc/{}", name);
        let _ = remove_directory_recursive(&config_dir);

        let data_dir = alloc::format!("/var/lib/{}", name);
        let _ = remove_directory_recursive(&data_dir);
    }

    unregister_package(name)?;
    let _ = super::manifest::remove_cached_manifest(name);

    if !options.no_scripts {
        run_post_remove(name, "")?;
    }

    crate::info!("npkg: {} removed", name);
    Ok(())
}

fn is_config_file(path: &str) -> bool {
    path.starts_with("/etc/") || path.ends_with(".conf") || path.ends_with(".cfg")
}

fn remove_directory_recursive(path: &str) -> NpkgResult<()> {
    let entries = crate::fs::vfs::get_vfs()
        .and_then(|vfs| vfs.list_dir(path).ok())
        .unwrap_or_default();

    for entry in entries {
        let full_path = alloc::format!("{}/{}", path, entry);
        if crate::fs::is_directory(&full_path) {
            remove_directory_recursive(&full_path)?;
        } else {
            let _ = crate::fs::unlink(&full_path);
        }
    }

    let _ = crate::fs::rmdir(path);
    Ok(())
}

pub fn upgrade_package(name: &str, options: &UpgradeOptions) -> NpkgResult<()> {
    upgrade_packages(&[name], options)
}

pub fn upgrade_packages(names: &[&str], options: &UpgradeOptions) -> NpkgResult<()> {
    for name in names {
        if !is_installed(name) {
            return Err(NpkgError::NotInstalled(String::from(*name)));
        }
    }

    let resolution = if options.no_deps {
        let mut result = ResolutionResult {
            to_install: Vec::new(),
            to_upgrade: Vec::new(),
            to_remove: Vec::new(),
            satisfied: Vec::new(),
            optional: Vec::new(),
        };

        for name in names {
            let current = query_by_name(name)
                .ok_or_else(|| NpkgError::NotInstalled(String::from(*name)))?;

            let latest = super::repository::find_package(name)
                .ok_or_else(|| NpkgError::PackageNotFound(String::from(*name)))?;

            if latest.meta.version > current.meta.version {
                result.to_upgrade.push((latest, current.meta.version));
            } else {
                result.satisfied.push(String::from(*name));
            }
        }

        result
    } else {
        resolve_dependencies(names)?
    };

    if resolution.to_upgrade.is_empty() && resolution.to_install.is_empty() {
        if !resolution.satisfied.is_empty() {
            return Err(NpkgError::UpgradeNotNeeded(resolution.satisfied[0].clone()));
        }
    }

    if options.download_only {
        for (pkg, _) in &resolution.to_upgrade {
            let _ = download_package(pkg)?;
        }
        return Ok(());
    }

    for (pkg, _old_version) in resolution.to_upgrade {
        let reason = query_by_name(&pkg.meta.name)
            .map(|p| p.install_reason)
            .unwrap_or(InstallReason::Explicit);

        let install_opts = InstallOptions {
            force: true,
            no_deps: true,
            no_scripts: options.no_scripts,
            download_only: false,
            as_dependency: reason == InstallReason::Dependency,
            reinstall: true,
        };

        install_single_package(&pkg, reason, &install_opts)?;
    }

    Ok(())
}

pub fn upgrade_all(options: &UpgradeOptions) -> NpkgResult<usize> {
    let installed = super::database::query_installed();
    let names: Vec<&str> = installed.iter().map(|p| p.meta.name.as_str()).collect();

    if names.is_empty() {
        return Ok(0);
    }

    let resolution = resolve_dependencies(&names)?;
    let count = resolution.to_upgrade.len();

    if count == 0 {
        return Ok(0);
    }

    if options.download_only {
        for (pkg, _) in &resolution.to_upgrade {
            let _ = download_package(pkg)?;
        }
        return Ok(count);
    }

    for (pkg, _old_version) in resolution.to_upgrade {
        let reason = query_by_name(&pkg.meta.name)
            .map(|p| p.install_reason)
            .unwrap_or(InstallReason::Explicit);

        let install_opts = InstallOptions {
            force: true,
            no_deps: true,
            no_scripts: options.no_scripts,
            download_only: false,
            as_dependency: reason == InstallReason::Dependency,
            reinstall: true,
        };

        install_single_package(&pkg, reason, &install_opts)?;
    }

    Ok(count)
}

pub fn reinstall_package(name: &str) -> NpkgResult<()> {
    let options = InstallOptions {
        reinstall: true,
        force: true,
        ..Default::default()
    };

    install_package(name, &options)
}
