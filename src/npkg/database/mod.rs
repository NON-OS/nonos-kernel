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

mod types;
mod init;
mod serialize;
mod save;
mod ops;
mod query;
mod maintenance;

pub use types::{DatabaseStats, PackageDatabase};
pub use init::init_database;
pub use save::{save_database, get_database};
pub use ops::{register_package, unregister_package};
pub use query::{query_installed, query_by_name, query_by_file, is_installed, get_installed_version};
pub use query::get_database_stats;
pub use maintenance::{mark_explicit, mark_dependency, get_orphans, verify_database_integrity};
