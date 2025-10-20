//! Browser manager: kernel-side orchestration for browser windows and process launch.

#![cfg(feature = "ui")]

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::ui::nonos_gui_bridge;
use crate::ui::nonos_event::Event;

/// Launcher trait for spawning user-space processes.
/// Implementations must validate inputs and run in userspace context.
pub trait ProcessLauncher: Send + Sync {
    fn launch(&self, executable: &str, argv: &[&str]) -> Result<u32, &'static str>;
}

static PROCESS_LAUNCHER: Mutex<Option<&'static dyn ProcessLauncher>> = Mutex::new(None);

pub fn register_process_launcher(launcher: &'static dyn ProcessLauncher) -> Result<(), &'static str> {
    let mut g = PROCESS_LAUNCHER.lock();
    if g.is_some() {
        return Err("process launcher already registered");
    }
    *g = Some(launcher);
    crate::log_info!("ui: process launcher registered");
    Ok(())
}

pub struct BrowserManager {
    next_instance: AtomicU32,
}

impl BrowserManager {
    pub fn new() -> Self {
        BrowserManager { next_instance: AtomicU32::new(1) }
    }

    /// Open URL: create a window and attempt to spawn the user-space browser via registered launcher.
    pub fn open_url(&self, url: &str) -> Result<(u32, Option<u32>), &'static str> {
        let title = alloc::format!("Browser - {}", url);
        let window_id = crate::ui::nonos_desktop::create_window(&title, 50, 50, 1024, 768)?;
        let g = PROCESS_LAUNCHER.lock();
        if let Some(launcher) = *g {
            match launcher.launch("/system/bin/browser", &[url]) {
                Ok(pid) => {
                    crate::log_info!("ui: launched browser pid={} for window {}", pid, window_id);
                    let _ = crate::ui::nonos_event::publish_event(Event::Custom { tag: "browser_launched".into(), payload: alloc::format!("pid={}", pid) });
                    Ok((window_id, Some(pid)))
                }
                Err(_) => {
                    crate::log_warn!("ui: process launcher failed to start browser");
                    Ok((window_id, None))
                }
            }
        } else {
            crate::log_warn!("ui: no process launcher registered; created window only");
            Ok((window_id, None))
        }
    }
}

static BROWSER_MANAGER: Mutex<Option<BrowserManager>> = Mutex::new(None);

pub fn init_browser_manager() {
    let mut g = BROWSER_MANAGER.lock();
    if g.is_none() {
        *g = Some(BrowserManager::new());
        crate::log_info!("ui: browser manager initialized");
    }
}

pub fn open_url(url: &str) -> Result<(u32, Option<u32>), &'static str> {
    let g = BROWSER_MANAGER.lock();
    if let Some(ref mgr) = *g {
        mgr.open_url(url)
    } else {
        Err("browser manager not initialized")
    }
}
