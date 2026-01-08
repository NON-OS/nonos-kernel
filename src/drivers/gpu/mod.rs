// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod constants;
mod driver;
pub mod error;
mod io;
mod surface;
mod vbe;

#[cfg(test)]
mod tests;

pub use constants::*;
pub use driver::{GpuDriver, GpuStats, GPU_ONCE};
pub use surface::{
    Backbuffer, DisplayMode, Framebuffer, GpuSurface, PixelFormat,
};
pub use vbe::{
    vbe_detect, vbe_disable, vbe_enable_lfb, vbe_read, vbe_write,
    get_current_mode, program_mode, set_panning_offset, set_virtual_size,
    validate_mode,
};

use spin::Mutex;
static GPU_HANDLE: spin::Once<&'static Mutex<GpuDriver>> = spin::Once::new();
pub fn init_gpu() -> Result<(), &'static str> {
    let handle = GpuDriver::init()?;
    GPU_HANDLE.call_once(|| handle);
    crate::log::logger::log_critical("GPU: Bochs VBE initialized");
    Ok(())
}

pub fn with_driver<T, F>(f: F) -> Option<T>
where
    F: FnOnce(&GpuDriver) -> T,
{
    GPU_HANDLE.get().map(|m| f(&m.lock()))
}

pub fn with_driver_mut<T, F>(f: F) -> Option<T>
where
    F: FnOnce(&mut GpuDriver) -> T,
{
    GPU_HANDLE.get().map(|m| f(&mut m.lock()))
}

pub fn set_mode_32bpp(width: u16, height: u16) -> Result<DisplayMode, &'static str> {
    GpuDriver::set_mode_32bpp(width, height)
}

pub fn disable_gpu() -> Result<(), &'static str> {
    GpuDriver::disable()
}

pub fn get_surface() -> Option<GpuSurface> {
    GpuDriver::get_surface()
}

pub fn is_initialized() -> bool {
    GPU_ONCE.get().is_some()
}

pub fn get_stats() -> Option<GpuStats> {
    with_driver(|drv| drv.get_stats())
}

pub fn get_mode() -> Option<DisplayMode> {
    with_driver(|drv| drv.surface.mode)
}

pub fn get_dimensions() -> Option<(u16, u16)> {
    with_driver(|drv| (drv.surface.mode.width, drv.surface.mode.height))
}

pub fn clear_screen(color: u32) {
    if let Some(surface) = get_surface() {
        surface.clear(color);
        surface.present(None);
    }
}
