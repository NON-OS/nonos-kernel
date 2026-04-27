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

pub mod cache;
pub mod commands;
pub mod database;
pub mod download;
pub mod error;
pub mod extract;
pub mod hooks;
pub mod installer;
pub mod manifest;
pub mod repository;
pub mod resolver;
pub mod sandbox;
pub mod signature;
pub mod types;

#[cfg(test)]
#[cfg(test)]
pub mod tests;

pub use types::{
    Architecture, Dependency, DependencyKind, FilePermissions, InstalledPackage, Package,
    PackageFile, PackageId, PackageKind, PackageMeta, PackageState, PackageVersion,
};

pub use error::{NpkgError, NpkgResult};

pub use manifest::{parse_manifest, serialize_manifest, Manifest, ManifestBuilder};

pub use signature::{
    generate_signing_keypair, sign_package, verify_package, PackageSignature, SigningKey,
    VerifyingKey,
};

pub use repository::{
    add_repository, find_package, find_package_version, get_package_url, get_repository_manager,
    init_repository_manager, list_repositories, remove_repository, search_packages,
    sync_all_repositories, sync_repository, Repository, RepositoryConfig, RepositoryKind,
};

pub use resolver::{
    check_conflicts, resolve_dependencies, DependencyResolver, ResolutionPlan, ResolutionResult,
};

pub use database::{
    get_database, get_installed_version, init_database, is_installed, query_by_file, query_by_name,
    query_installed, DatabaseStats, PackageDatabase,
};

pub use installer::{
    install_package, install_packages, reinstall_package, remove_package, remove_packages,
    upgrade_all, upgrade_package, InstallOptions, RemoveOptions, UpgradeOptions,
};

pub use download::{download_package, download_packages, verify_checksum, DownloadProgress};

pub use extract::{extract_package, list_package_contents, PackageArchive};

pub use commands::{
    cmd_clean, cmd_files, cmd_info, cmd_install, cmd_list, cmd_owner, cmd_remove, cmd_search,
    cmd_sync, cmd_upgrade, cmd_verify,
};

pub use cache::{cache_stats, clear_cache, get_cache_dir, CachePolicy, CacheStats};

pub use hooks::{
    run_post_install, run_post_remove, run_pre_install, run_pre_remove, PostInstallHook,
    PostRemoveHook, PreInstallHook, PreRemoveHook,
};

pub use sandbox::{install_sandboxed, verify_sandbox_integrity, SandboxConfig, SandboxedInstall};

pub fn init() -> NpkgResult<()> {
    database::init_database()?;
    repository::init_repository_manager()?;
    cache::init_cache()?;
    Ok(())
}
