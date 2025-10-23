//! Desktop manager: window creation, basic taskbar and compositor primitives.

#![cfg(feature = "ui")]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::process;

/// Maximum allowed framebuffer pixels to avoid unbounded allocations.
/// (e.g., 3840*2160 ~ 8.3M pixels; cap lower for typical embedded targets)
const MAX_FRAMEBUFFER_PIXELS: usize = 1920 * 1080 * 2; // allow up to 2x FHD as a conservative cap

/// Window description.
#[derive(Clone)]
pub struct Window {
    pub id: u32,
    pub title: alloc::string::String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub visible: bool,
    pub framebuffer: Vec<u32>, // RGBA
    pub process_id: u32,
}

/// Simple taskbar entry.
pub struct TaskbarApp {
    pub name: alloc::string::String,
    pub icon: Vec<u32>,
    pub window_id: Option<u32>,
    pub executable_path: alloc::string::String,
}

/// Clock widget (lightweight).
pub struct ClockWidget {
    pub format_24h: bool,
    pub show_seconds: bool,
}

/// System tray minimal struct.
pub struct SystemTray {
    pub icons: Vec<Vec<u32>>,
    pub notifications: Vec<alloc::string::String>,
}

/// Window compositor (very small).
pub struct WindowCompositor {
    pub framebuffer: Vec<u32>,
    pub width: u32,
    pub height: u32,
    pub dirty_regions: Vec<(u32, u32, u32, u32)>,
}

/// Desktop manager instance.
pub struct DesktopManager {
    windows: Mutex<BTreeMap<u32, Window>>,
    taskbar_apps: Mutex<Vec<TaskbarApp>>,
    compositor: Mutex<WindowCompositor>,
    next_window_id: AtomicU32,
}

static DESKTOP: Mutex<Option<DesktopManager>> = Mutex::new(None);

impl DesktopManager {
    /// Create a new DesktopManager with checked framebuffer allocation.
    pub fn new(width: u32, height: u32) -> Result<Self, &'static str> {
        let pixels = width as usize;
        let pixels = pixels.checked_mul(height as usize).ok_or("dimension overflow")?;
        if pixels > MAX_FRAMEBUFFER_PIXELS {
            return Err("requested framebuffer too large");
        }
        // Pre-allocate compositor framebuffer
        let mut fb = Vec::with_capacity(pixels);
        fb.resize(pixels, 0xFF000000); // opaque black

        Ok(DesktopManager {
            windows: Mutex::new(BTreeMap::new()),
            taskbar_apps: Mutex::new(Vec::new()),
            compositor: Mutex::new(WindowCompositor { framebuffer: fb, width, height, dirty_regions: Vec::new() }),
            next_window_id: AtomicU32::new(1),
        })
    }

    /// Start compositor loop (platform must implement actual rendering).
    pub fn start_compositor(&self) {
        crate::log_info!("ui: compositor started");
        // Platform-specific compositor loop should be registered as a callback into this module.
    }

    /// Create a window, return id.
    pub fn create_window(&self, title: &str, x: i32, y: i32, width: u32, height: u32) -> Result<u32, &'static str> {
        let id = self.next_window_id.fetch_add(1, Ordering::SeqCst);
        let size = (width as usize).checked_mul(height as usize).ok_or("window size overflow")?;
        if size > MAX_FRAMEBUFFER_PIXELS {
            return Err("window framebuffer too large");
        }
        let mut fb = Vec::with_capacity(size);
        fb.resize(size, 0xFFFFFFFF); // white

        let pid = process::current_pid().unwrap_or(0);
        let w = Window { id, title: alloc::string::String::from(title), x, y, width, height, visible: true, framebuffer: fb, process_id: pid };
        self.windows.lock().insert(id, w);
        self.mark_dirty_region(x as u32, y as u32, width, height);
        crate::log_info!("ui: created window id={}", id);
        Ok(id)
    }

    fn mark_dirty_region(&self, x: u32, y: u32, width: u32, height: u32) {
        let mut comp = self.compositor.lock();
        comp.dirty_regions.push((x, y, width, height));
    }

    pub fn add_taskbar_app(&self, name: &str, exec: &str, icon_color: u32) {
        let icon = vec![icon_color; 32 * 32];
        self.taskbar_apps.lock().push(TaskbarApp { name: name.into(), icon, window_id: None, executable_path: exec.into() });
    }

    pub fn get_window(&self, id: u32) -> Option<Window> {
        self.windows.lock().get(&id).cloned()
    }
}

/// Initialize global desktop manager (idempotent).
pub fn init_desktop_manager(width: u32, height: u32) -> Result<(), &'static str> {
    let mut g = DESKTOP.lock();
    if g.is_some() {
        return Err("desktop manager already initialized");
    }
    let dm = DesktopManager::new(width, height)?;
    // register some default apps in a safe manner
    dm.add_taskbar_app("File Manager", "/system/bin/filemanager", 0xFF4A90E2);
    dm.add_taskbar_app("Terminal", "/system/bin/terminal", 0xFF000000);
    *g = Some(dm);
    crate::log_info!("ui: desktop manager initialized");
    Ok(())
}

/// Create window helper used by gui_bridge.
pub fn create_window(title: &str, x: i32, y: i32, width: u32, height: u32) -> Result<u32, &'static str> {
    let g = DESKTOP.lock();
    if let Some(ref dm) = *g {
        dm.create_window(title, x, y, width, height)
    } else {
        Err("desktop manager not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_init_create_window() {
        let _ = init_desktop_manager(800, 600);
        let id = create_window("t", 0, 0, 200, 100).unwrap();
        assert!(id > 0);
    }
}
