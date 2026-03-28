// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

mod types;
mod repo;
mod manager;
mod config;
mod sync;
mod query;
mod api;

pub use types::{RepositoryKind, RepositoryConfig};
pub use repo::Repository;
pub use manager::{init_repository_manager, get_repository_manager};
pub use api::{add_repository, remove_repository, list_repositories};
pub use sync::{sync_repository, sync_all_repositories};
pub use query::{find_package, find_package_version, search_packages, get_package_url};
