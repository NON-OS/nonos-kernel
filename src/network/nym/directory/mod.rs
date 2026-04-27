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

pub mod cache;
pub mod fetch;
pub mod gateways;
pub mod mixnodes;
pub mod validators;

pub use cache::{get_directory_cache, DirectoryCache};
pub use fetch::fetch_topology;
pub use gateways::{fetch_gateways, select_gateway};
pub use mixnodes::{fetch_mixnodes, select_mixnode_by_layer};
pub use validators::{Validator, VALIDATORS};

pub fn get_cached_topology() -> &'static spin::Mutex<DirectoryCache> {
    get_directory_cache()
}
