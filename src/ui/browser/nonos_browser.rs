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

//! Browser manager: kernel-side orchestration for browser windows and process launch.

#![cfg(feature = "ui")]

use spin::Mutex;

use crate::ui::event::Event;

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
}

impl BrowserManager {
    pub fn new() -> Self {
        BrowserManager { }
    }

    /// Open URL: create a window and attempt to spawn the user-space browser via registered launcher.
    pub fn open_url(&self, url: &str) -> Result<(u32, Option<u32>), &'static str> {
        let title = alloc::format!("Browser - {}", url);
        let window_id = crate::ui::desktop::create_window(&title, 50, 50, 1024, 768)?;
        let g = PROCESS_LAUNCHER.lock();
        if let Some(launcher) = *g {
            match launcher.launch("/system/bin/browser", &[url]) {
                Ok(pid) => {
                    crate::log_info!("ui: launched browser pid={} for window {}", pid, window_id);
                    let _ = crate::ui::event::publish_event(Event::Custom { tag: "browser_launched".into(), payload: alloc::format!("pid={}", pid) });
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
