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

pub mod types;
pub mod error;
pub mod manifest;
pub mod signature;
pub mod repository;
pub mod resolver;
pub mod database;
pub mod installer;
pub mod download;
pub mod extract;
pub mod commands;
pub mod cache;
pub mod hooks;
pub mod sandbox;

pub use types::{
    Package, PackageId, PackageVersion, PackageMeta, PackageState,
    Dependency, DependencyKind, Architecture, PackageKind,
    InstalledPackage, PackageFile, FilePermissions,
};

pub use error::{NpkgError, NpkgResult};

pub use manifest::{
    Manifest, ManifestBuilder, parse_manifest, serialize_manifest,
};

pub use signature::{
    PackageSignature, SigningKey, VerifyingKey,
    sign_package, verify_package, generate_signing_keypair,
};

pub use repository::{
    Repository, RepositoryConfig, RepositoryKind,
    add_repository, remove_repository, list_repositories,
    sync_repository, sync_all_repositories,
    get_repository_manager, init_repository_manager,
};

pub use resolver::{
    DependencyResolver, ResolutionResult, ResolutionPlan,
    resolve_dependencies, check_conflicts,
};

pub use database::{
    PackageDatabase, DatabaseStats,
    get_database, init_database,
    query_installed, query_by_name, query_by_file,
    is_installed, get_installed_version,
};

pub use installer::{
    install_package, install_packages,
    remove_package, remove_packages,
    upgrade_package, upgrade_all,
    reinstall_package,
    InstallOptions, RemoveOptions, UpgradeOptions,
};

pub use download::{
    download_package, download_packages,
    verify_checksum, DownloadProgress,
};

pub use extract::{
    extract_package, PackageArchive,
    list_package_contents,
};

pub use commands::{
    cmd_install, cmd_remove, cmd_upgrade, cmd_search,
    cmd_info, cmd_list, cmd_sync, cmd_clean,
    cmd_verify, cmd_files, cmd_owner,
};

pub use cache::{
    get_cache_dir, clear_cache, cache_stats,
    CacheStats, CachePolicy,
};

pub use hooks::{
    PreInstallHook, PostInstallHook,
    PreRemoveHook, PostRemoveHook,
    run_pre_install, run_post_install,
    run_pre_remove, run_post_remove,
};

pub use sandbox::{
    SandboxConfig, SandboxedInstall,
    install_sandboxed, verify_sandbox_integrity,
};

pub fn init() -> NpkgResult<()> {
    database::init_database()?;
    repository::init_repository_manager()?;
    cache::init_cache()?;
    Ok(())
}
