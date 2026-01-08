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

use spin::Mutex;
use x86_64::VirtAddr;
use crate::drivers::pci::{self, PciDevice, pci_read_config32, pci_write_config32};
use crate::memory::mmio::mmio_w32;
use super::constants::*;
use super::surface::*;
use super::vbe;

#[derive(Default, Clone)]
pub struct GpuStats {
    pub frames_rendered: u64,
    pub commands_executed: u64,
    pub memory_allocated: u64,
    pub gpu_errors: u64,
    pub surfaces_created: u64,
    pub shaders_loaded: u64,
    pub vendor_id: u32,
    pub device_id: u32,
}

pub struct GpuDriver {
    pub vendor_id: u16,
    pub device_id: u16,
    pub surface: GpuSurface,
}

pub static GPU_ONCE: spin::Once<Mutex<GpuDriver>> = spin::Once::new();

impl GpuDriver {
    fn pci_enable_mem_and_busmaster(dev: &PciDevice) {
        let mut cmd = pci_read_config32(dev.bus, dev.device, dev.function, PCI_COMMAND_OFFSET) as u16;
        let mut changed = false;
        if (cmd & PCI_CMD_MEM_ENABLE) == 0 {
            cmd |= PCI_CMD_MEM_ENABLE;
            changed = true;
        }
        if (cmd & PCI_CMD_BUS_MASTER) == 0 {
            cmd |= PCI_CMD_BUS_MASTER;
            changed = true;
        }

        if changed {
            let full = (pci_read_config32(dev.bus, dev.device, dev.function, PCI_COMMAND_OFFSET) & 0xFFFF_0000)
                | (cmd as u32);
            pci_write_config32(dev.bus, dev.device, dev.function, PCI_COMMAND_OFFSET, full);
        }
    }

    fn pick_device() -> Option<PciDevice> {
        let devices = pci::scan_and_collect();
        if let Some(d) = devices.iter()
            .find(|d| d.vendor_id == VENDOR_QEMU && d.device_id == DEVICE_STD_VGA)
            .cloned()
        {
            return Some(d);
        }

        devices.into_iter().find(|d| d.class == CLASS_DISPLAY)
    }

    pub fn init() -> Result<&'static Mutex<GpuDriver>, &'static str> {
        if let Some(existing) = GPU_ONCE.get() {
            return Ok(existing);
        }

        let dev = Self::pick_device().ok_or("GPU: no suitable display controller found")?;

        Self::pci_enable_mem_and_busmaster(&dev);

        let bar0 = dev.get_bar(0).ok_or("GPU: BAR0 not present")?;
        let (fb_phys, fb_len) = bar0.mmio_region().ok_or("GPU: BAR0 not MMIO")?;
        let fb_virt = fb_phys.as_u64() as usize;
        if !vbe::vbe_detect() {
            return Err("GPU: Bochs VBE not detected");
        }

        let pitch = vbe::validate_mode(fb_len, DEFAULT_WIDTH, DEFAULT_HEIGHT, DEFAULT_BPP)?;
        let prog_pitch = vbe::program_mode(DEFAULT_WIDTH, DEFAULT_HEIGHT, DEFAULT_BPP);
        let pitch = pitch.min(prog_pitch);
        // SAFETY: fb_virt is a valid MMIO address from PCI BAR0
        unsafe { mmio_w32(VirtAddr::new(fb_virt as u64), 0) };
        let backbuf_bytes = pitch as usize * DEFAULT_HEIGHT as usize;
        let backbuf = Backbuffer::new(backbuf_bytes)?;
        let surface = GpuSurface {
            mode: DisplayMode {
                width: DEFAULT_WIDTH,
                height: DEFAULT_HEIGHT,
                bpp: DEFAULT_BPP,
                pitch,
            },
            format: PixelFormat::X8R8G8B8,
            fb: Framebuffer::new(fb_phys, fb_len, fb_virt),
            backbuf,
        };

        let driver = GpuDriver {
            vendor_id: dev.vendor_id,
            device_id: dev.device_id,
            surface,
        };

        let m = Mutex::new(driver);
        let r = GPU_ONCE.call_once(|| m);
        Ok(r)
    }

    pub fn set_mode_32bpp(width: u16, height: u16) -> Result<DisplayMode, &'static str> {
        let drv = GPU_ONCE.get().ok_or("GPU not initialized")?;
        let mut g = drv.lock();
        let pitch = vbe::validate_mode(g.surface.fb.fb_len, width, height, 32)?;
        let prog_pitch = vbe::program_mode(width, height, 32);
        let pitch = pitch.min(prog_pitch);
        let need_bytes = pitch as usize * height as usize;
        g.surface.backbuf = Backbuffer::new(need_bytes)?;
        g.surface.mode = DisplayMode {
            width,
            height,
            bpp: 32,
            pitch,
        };
      
        Ok(g.surface.mode)
    }

    pub fn disable() -> Result<(), &'static str> {
        if GPU_ONCE.get().is_none() {
            return Ok(());
        }
        vbe::vbe_disable();
        Ok(())
    }

    pub fn get_surface() -> Option<GpuSurface> {
        GPU_ONCE.get().map(|m| m.lock().surface.clone())
    }

    pub fn get_stats(&self) -> GpuStats {
        GpuStats {
            frames_rendered: 0,
            commands_executed: 0,
            memory_allocated: self.surface.mode.pitch as u64 * self.surface.mode.height as u64,
            gpu_errors: 0,
            surfaces_created: 1,
            shaders_loaded: 0,
            vendor_id: self.vendor_id as u32,
            device_id: self.device_id as u32,
        }
    }
}
