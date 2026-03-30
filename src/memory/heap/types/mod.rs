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

mod bootstrap;
mod header;
mod statistics;
mod stats;
mod allocator;
mod alloc_impl;
mod dealloc_impl;
mod global_alloc;

pub use bootstrap::BootstrapHeapMemory;
pub use header::AllocationHeader;
pub use statistics::HeapStatistics;
pub use stats::HeapStats;
pub use allocator::SecureHeapAllocator;
