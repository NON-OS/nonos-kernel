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

mod init;
mod maintenance;
mod ops;
mod query;
mod save;
mod serialize;
mod types;

pub use init::init_database;
pub use maintenance::{get_orphans, mark_dependency, mark_explicit, verify_database_integrity};
pub use ops::{register_package, unregister_package};
pub use query::get_database_stats;
pub use query::{
    get_installed_version, is_installed, query_by_file, query_by_name, query_installed,
};
pub use save::{get_database, save_database};
pub use types::{DatabaseStats, PackageDatabase};
