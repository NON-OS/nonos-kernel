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

mod address_space;
mod helpers;
mod mapping;
mod page_size;
mod permissions;
mod stats;

pub use address_space::AddressSpace;
pub use helpers::get_timestamp;
pub use mapping::PageMapping;
pub use page_size::PageSize;
pub use permissions::PagePermissions;
pub use stats::PagingStats;
