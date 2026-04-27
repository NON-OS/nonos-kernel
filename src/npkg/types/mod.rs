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

mod architecture;
mod dependency;
mod file_types;
mod installed;
mod package;
mod package_id;
mod package_kind;
mod state;
mod version;
mod version_parse;
mod version_req;

pub use architecture::Architecture;
pub use dependency::Dependency;
pub use file_types::{FilePermissions, PackageFile};
pub use installed::{InstallReason, InstalledPackage};
pub use package::{Package, PackageMeta};
pub use package_id::PackageId;
pub use package_kind::PackageKind;
pub use state::{DependencyKind, PackageState};
pub use version::PackageVersion;
pub use version_req::VersionRequirement;
