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

mod api;
mod config;
mod manager;
mod query;
mod repo;
mod sync;
mod types;

pub use api::{add_repository, list_repositories, remove_repository};
pub use manager::{get_repository_manager, init_repository_manager};
pub use query::{find_package, find_package_version, get_package_url, search_packages};
pub use repo::Repository;
pub use sync::{sync_all_repositories, sync_repository};
pub use types::{RepositoryConfig, RepositoryKind};
