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

mod api;
mod core;
mod io;

pub use api::{
    get_mapped_regions, get_region_info, get_stats, init, is_mmio_region, list_regions,
    map_device_memory, map_framebuffer, map_mmio, unmap_mmio, validate_mmio_access,
};
pub use core::MmioManager;
pub use io::{read16, read32, read64, read8, write16, write32, write64, write8};
