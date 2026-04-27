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

mod builder;
mod cache;
mod parse;
mod parse_helpers;
mod serialize;
mod types;

pub use builder::ManifestBuilder;
pub use cache::{cache_manifest, get_cached_manifest, remove_cached_manifest};
pub use parse::parse_manifest;
pub use serialize::serialize_manifest;
pub use types::Manifest;
