//! Bochs/QEMU Std VGA VBE GPU Driver 

use core::{arch::asm, ptr};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use crate::drivers::pci::{self, PciBar, PciDevice, pci_read_config32, pci_write_config32};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use crate::memory::mmio::mmio_w32;

const VENDOR_QEMU: u16 = 0x1234;
const DEVICE_STD_VGA: u16 = 0x1111;
const CLASS_DISPLAY: u8 = 0x03;

// Bochs VBE I/O ports
const VBE_INDEX_PORT: u16 = 0x1CE;
const VBE_DATA_PORT: u16 = 0x1CF;

// Bochs VBE registers
const VBE_DISPI_INDEX_ID: u16 = 0x0;
const VBE_DISPI_INDEX_XRES: u16 = 0x1;
const VBE_DISPI_INDEX_YRES: u16 = 0x2;
const VBE_DISPI_INDEX_BPP: u16 = 0x3;
const VBE_DISPI_INDEX_ENABLE: u16 = 0x4;
const VBE_DISPI_INDEX_BANK: u16 = 0x5;
const VBE_DISPI_INDEX_VIRT_WIDTH: u16 = 0x6;
const VBE_DISPI_INDEX_VIRT_HEIGHT: u16 = 0x7;
const VBE_DISPI_INDEX_X_OFFSET: u16 = 0x8;
const VBE_DISPI_INDEX_Y_OFFSET: u16 = 0x9;

// Bochs flags and values
const VBE_DISPI_ENABLED: u16 = 0x01;
const VBE_DISPI_LFB_ENABLED: u16 = 0x40;
const VBE_DISPI_NOCLEARMEM: u16 = 0x80;
const VBE_DISPI_ID_MAGIC: u16 = 0xB0C5;

// Defaults
const DEFAULT_WIDTH: u16 = 1024;
const DEFAULT_HEIGHT: u16 = 768;
const DEFAULT_BPP: u16 = 32;

// PCI Command register bits
const PCI_COMMAND_OFFSET: u8 = 0x04;
const PCI_CMD_IO_ENABLE: u16 = 1 << 0;
const PCI_CMD_MEM_ENABLE: u16 = 1 << 1;
const PCI_CMD_BUS_MASTER: u16 = 1 << 2;

// Port I/O helpers
#[inline(always)]
unsafe fn outw(port: u16, val: u16) {
    asm!("out dx, ax", in("dx") port, in("ax") val, options(nostack, preserves_flags));
}
#[inline(always)]
unsafe fn inw(port: u16) -> u16 {
    let mut val: u16;
    asm!("in ax, dx", in("dx") port, out("ax") val, options(nostack, preserves_flags));
    val
}

#[derive(Clone, Copy)]
pub enum PixelFormat {
    X8R8G8B8, // little-endian in memory: B,G,R,X
}

#[derive(Clone, Copy)]
pub struct DisplayMode {
    pub width: u16,
    pub height: u16,
    pub bpp: u16,   // only 32 supported here
    pub pitch: u32, // bytes per scanline
}

#[derive(Clone)]
pub struct Framebuffer {
    pub fb_phys: PhysAddr,
    pub fb_len: usize, // total LFB length from BAR
    pub fb_virt: usize, // VA mapping 
}

#[derive(Clone)]
pub struct Backbuffer {
    va: usize,
    len: usize,
}
impl Backbuffer {
    fn new(bytes: usize) -> Result<Self, &'static str> {
        // Coherent DMA region is convenient contiguous RAM for fast CPU copies
        let constraints = DmaConstraints {
            alignment: 64,
            max_segment_size: bytes,
            dma32_only: false,
            coherent: true,
        };
        let dma_region = alloc_dma_coherent(bytes, constraints)?;
        let (va, _pa) = (dma_region.virt_addr, dma_region.phys_addr);
        unsafe { ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, bytes) };
        Ok(Backbuffer { va: va.as_u64() as usize, len: bytes })
    }
    #[inline]
    fn as_mut_ptr(&self) -> *mut u8 {
        self.va as *mut u8
    }
}

#[derive(Clone)]
pub struct GpuSurface {
    pub mode: DisplayMode,
    pub format: PixelFormat,
    pub fb: Framebuffer,
    pub backbuf: Backbuffer,
}

impl GpuSurface {
    pub fn clear(&self, color: u32) {
        // Fill backbuffer; present() will blit to LFB
        let pixels = (self.mode.pitch as usize / 4) * self.mode.height as usize;
        let mut p = self.backbuf.as_mut_ptr() as *mut u32;
        for _ in 0..pixels {
            unsafe { ptr::write_volatile(p, color) };
            p = unsafe { p.add(1) };
        }
    }

    pub fn put_pixel(&self, x: u16, y: u16, color: u32) {
        if x >= self.mode.width || y >= self.mode.height {
            return;
        }
        let stride_px = (self.mode.pitch / 4) as usize;
        let offset = y as usize * stride_px + x as usize;
        let ptr_u32 = self.backbuf.as_mut_ptr() as *mut u32;
        unsafe { ptr::write_volatile(ptr_u32.add(offset), color) };
    }

    pub fn fill_rect(&self, x: u16, y: u16, w: u16, h: u16, color: u32) {
        if w == 0 || h == 0 {
            return;
        }
        let x2 = x.saturating_add(w).min(self.mode.width);
        let y2 = y.saturating_add(h).min(self.mode.height);
        if x >= self.mode.width || y >= self.mode.height {
            return;
        }
        let stride_px = (self.mode.pitch / 4) as usize;
        let mut row_ptr = (self.backbuf.as_mut_ptr() as *mut u32)
            .wrapping_add(y as usize * stride_px + x as usize);
        for _row in y..y2 {
            let mut p = row_ptr;
            for _col in x..x2 {
                unsafe { ptr::write_volatile(p, color) };
                p = unsafe { p.add(1) };
            }
            row_ptr = unsafe { row_ptr.add(stride_px) };
        }
    }

    pub fn blit(&self, x: u16, y: u16, src: &[u32], src_w: u16, src_h: u16) {
        if src_w == 0 || src_h == 0 {
            return;
        }
        let x2 = x.saturating_add(src_w).min(self.mode.width);
        let y2 = y.saturating_add(src_h).min(self.mode.height);
        if x >= self.mode.width || y >= self.mode.height {
            return;
        }
        let copy_w = (x2 - x) as usize;
        let stride_px = (self.mode.pitch / 4) as usize;
        for row in 0..(y2 - y) as usize {
            let dst_row = (y as usize + row) * stride_px + x as usize;
            let src_row = row * src_w as usize;
            let dst_ptr = (self.backbuf.as_mut_ptr() as *mut u32).wrapping_add(dst_row);
            let src_ptr = src.as_ptr().wrapping_add(src_row);
            unsafe {
                for i in 0..copy_w {
                    let px = ptr::read_volatile(src_ptr.add(i));
                    ptr::write_volatile(dst_ptr.add(i), px);
                }
            }
        }
    }

    /// Present backbuffer to LFB (optionally a clipped rectangle).
    /// If rect is None, present the entire surface.
    pub fn present(&self, rect: Option<(u16, u16, u16, u16)>) {
        let (x, y, w, h) = rect.unwrap_or((0, 0, self.mode.width, self.mode.height));
        if w == 0 || h == 0 {
            return;
        }
        let x2 = x.saturating_add(w).min(self.mode.width);
        let y2 = y.saturating_add(h).min(self.mode.height);
        if x >= self.mode.width || y >= self.mode.height {
            return;
        }

        let bytes_per_px = (self.mode.bpp / 8) as usize;
        let stride_bytes = self.mode.pitch as usize;

        // Validate we won't write past LFB (defensive)
        let max_needed = (y2 as usize - 0) * stride_bytes;
        if max_needed > self.fb.fb_len {
            // Clamp to framebuffer length
            return;
        }

        for row in y as usize..y2 as usize {
            let line_bytes = (x2 as usize - x as usize) * bytes_per_px;
            let dst = (self.fb.fb_virt + row * stride_bytes + (x as usize) * bytes_per_px) as *mut u8;
            let src =
                (self.backbuf.va + row * stride_bytes + (x as usize) * bytes_per_px) as *const u8;
            unsafe {
                // volatile copy to avoid reordering across MMIO
                for i in 0..line_bytes {
                    let b = ptr::read_volatile(src.add(i));
                    ptr::write_volatile(dst.add(i), b);
                }
            }
        }
    }
}

pub struct GpuDriver {
    pub vendor_id: u16,
    pub device_id: u16,
    pub surface: GpuSurface,
}

static GPU_ONCE: spin::Once<Mutex<GpuDriver>> = spin::Once::new();

impl GpuDriver {
    // ----- Bochs VBE helpers -----

    fn vbe_write(index: u16, value: u16) {
        unsafe {
            outw(VBE_INDEX_PORT, index);
            outw(VBE_DATA_PORT, value);
        }
    }

    fn vbe_read(index: u16) -> u16 {
        unsafe {
            outw(VBE_INDEX_PORT, index);
            inw(VBE_DATA_PORT)
        }
    }

    fn vbe_detect() -> bool {
        Self::vbe_read(VBE_DISPI_INDEX_ID) == VBE_DISPI_ID_MAGIC
    }

    fn vbe_disable() {
        Self::vbe_write(VBE_DISPI_INDEX_ENABLE, 0);
    }

    fn vbe_enable_lfb() {
        Self::vbe_write(
            VBE_DISPI_INDEX_ENABLE,
            VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM,
        );
    }

    fn program_mode(width: u16, height: u16, bpp: u16) -> u32 {
        // Disable before programming new mode
        Self::vbe_disable();

        // Program resolution and bpp
        Self::vbe_write(VBE_DISPI_INDEX_XRES, width);
        Self::vbe_write(VBE_DISPI_INDEX_YRES, height);
        Self::vbe_write(VBE_DISPI_INDEX_BPP, bpp);

        // Program virtual size and offsets = physical for simplicity
        Self::vbe_write(VBE_DISPI_INDEX_VIRT_WIDTH, width);
        Self::vbe_write(VBE_DISPI_INDEX_VIRT_HEIGHT, height);
        Self::vbe_write(VBE_DISPI_INDEX_X_OFFSET, 0);
        Self::vbe_write(VBE_DISPI_INDEX_Y_OFFSET, 0);

        // Enable LFB
        Self::vbe_enable_lfb();

        // Pitch is width * bytes_per_pixel for Bochs
        (width as u32) * (bpp as u32 / 8)
    }

    // ----- PCI helpers -----

    fn pci_enable_mem_and_busmaster(dev: &PciDevice) {
        // Read Command register (offset 0x04, low 16 bits)
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

    // ----- Device selection and init -----

    fn pick_device() -> Option<PciDevice> {
        let devices = pci::scan_and_collect();
        if let Some(d) = devices
            .iter()
            .find(|d| d.vendor_id == VENDOR_QEMU && d.device_id == DEVICE_STD_VGA)
            .cloned()
        {
            return Some(d);
        }
        devices.into_iter().find(|d| d.class == CLASS_DISPLAY)
    }

    fn validate_mode_against_bar(size_bytes: usize, width: u16, height: u16, bpp: u16) -> Result<u32, &'static str> {
        if bpp != 32 {
            return Err("Only 32bpp is supported");
        }
        let pitch = width as u32 * (bpp as u32 / 8);
        let needed = pitch as usize * height as usize;
        if needed > size_bytes {
            return Err("Requested mode exceeds framebuffer BAR size");
        }
        Ok(pitch)
    }

    pub fn init() -> Result<&'static Mutex<GpuDriver>, &'static str> {
        if let Some(existing) = GPU_ONCE.get() {
            return Ok(existing);
        }

        let dev = Self::pick_device().ok_or("GPU: no suitable display controller found")?;

        // Enable MEM + BusMaster
        Self::pci_enable_mem_and_busmaster(&dev);

        // BAR0 expected to be LFB (QEMU Bochs)
        let (fb_phys, fb_len, fb_virt) = match dev.get_bar(0)? {
            PciBar::Memory { address, size, .. } => {
                let pa = address;
                let len = size;
                // if your platform uses ioremap, ensure VA == PA mapping here.
                (pa, len, address.as_u64() as usize)
            }
            _ => return Err("GPU: BAR0 not MMIO"),
        };

        if !Self::vbe_detect() {
            return Err("GPU: Bochs VBE not detected");
        }

        // Validate default mode against BAR size
        let pitch = Self::validate_mode_against_bar(fb_len, DEFAULT_WIDTH, DEFAULT_HEIGHT, DEFAULT_BPP)?;
        let prog_pitch = Self::program_mode(DEFAULT_WIDTH, DEFAULT_HEIGHT, DEFAULT_BPP);
        let pitch = pitch.min(prog_pitch);

        // Touch LFB to ensure mapping present
        unsafe { mmio_w32(VirtAddr::new(fb_virt as u64), 0) };

        // Create backbuffer sized to full surface
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
            fb: Framebuffer {
                fb_phys,
                fb_len,
                fb_virt,
            },
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

        // Validate against BAR size before programming
        let pitch = Self::validate_mode_against_bar(g.surface.fb.fb_len, width, height, 32)?;
        let prog_pitch = Self::program_mode(width, height, 32);
        let pitch = pitch.min(prog_pitch);

        // Recreate backbuffer sized for new mode
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
        // Disable LFB output (keeps memory mapped)
        Self::vbe_disable();
        Ok(())
    }

    pub fn get_surface() -> Option<GpuSurface> {
        GPU_ONCE.get().map(|m| m.lock().surface.clone())
    }

    pub fn get_stats(&self) -> GpuStats {
        GpuStats {
            frames_rendered: 0,
            commands_executed: 0,
            memory_allocated: (self.surface.mode.pitch as u64) * (self.surface.mode.height as u64),
            gpu_errors: 0,
            surfaces_created: 1,
            shaders_loaded: 0,
            vendor_id: self.vendor_id as u32,
            device_id: self.device_id as u32,
        }
    }
}

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

// Public API

static mut GPU_HANDLE: Option<&'static Mutex<GpuDriver>> = None;

pub fn init_gpu() -> Result<(), &'static str> {
    let handle = GpuDriver::init()?;
    unsafe { GPU_HANDLE = Some(handle) };
    crate::log::logger::log_critical("✓ GPU: Bochs VBE initialized (double-buffered 32bpp)");
    Ok(())
}

pub fn with_driver<T, F>(f: F) -> Option<T>
where
    F: FnOnce(&GpuDriver) -> T,
{
    unsafe { GPU_HANDLE.as_ref().map(|m| f(&*m.lock())) }
}

pub fn set_mode_32bpp(width: u16, height: u16) -> Result<DisplayMode, &'static str> {
    GpuDriver::set_mode_32bpp(width, height)
}

pub fn disable_gpu() -> Result<(), &'static str> {
    GpuDriver::disable()
}
