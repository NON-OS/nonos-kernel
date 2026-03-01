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
mod constants;
mod driver;
pub mod error;
mod io;
mod surface;
mod vbe;

#[cfg(test)]
mod tests;

pub use api::{
    clear_screen, disable_gpu, get_dimensions, get_mode, get_stats, get_surface, init_gpu,
    is_initialized, set_mode_32bpp, with_driver, with_driver_mut,
};
pub use constants::*;
pub use driver::{GpuDriver, GpuStats, GPU_ONCE};
pub use surface::{Backbuffer, DisplayMode, Framebuffer, GpuSurface, PixelFormat};
pub use vbe::{
    get_current_mode, program_mode, set_panning_offset, set_virtual_size, validate_mode,
    vbe_detect, vbe_disable, vbe_enable_lfb, vbe_read, vbe_write,
};
