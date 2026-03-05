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


extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::RwLock;

use super::tabs::BrowserTab;

static BROWSER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static ACTIVE_TAB_ID: AtomicU32 = AtomicU32::new(0);
static BROWSER_STATE: RwLock<Option<BrowserStateInner>> = RwLock::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    None,
    System,
    Onion,
    Custom,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub mode: ProxyMode,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            mode: ProxyMode::Onion,
            host: String::from("127.0.0.1"),
            port: 9050,
            username: None,
            password: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrowserSettings {
    pub javascript_enabled: bool,
    pub cookies_enabled: bool,
    pub tracking_protection: bool,
    pub fingerprint_protection: bool,
    pub https_only: bool,
    pub do_not_track: bool,
    pub referrer_policy: ReferrerPolicy,
    pub user_agent: String,
    pub proxy: ProxyConfig,
}

impl Default for BrowserSettings {
    fn default() -> Self {
        Self {
            javascript_enabled: false,
            cookies_enabled: false,
            tracking_protection: true,
            fingerprint_protection: true,
            https_only: true,
            do_not_track: true,
            referrer_policy: ReferrerPolicy::NoReferrer,
            user_agent: String::from("NONOS/1.0"),
            proxy: ProxyConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

struct BrowserStateInner {
    tabs: Vec<BrowserTab>,
    settings: BrowserSettings,
    next_tab_id: u32,
}

#[derive(Debug, Clone)]
pub struct BrowserState {
    pub tab_count: usize,
    pub active_tab_id: u32,
    pub settings: BrowserSettings,
}

pub fn init() {
    if BROWSER_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    let home_tab = BrowserTab::new(0, "about:blank");

    let inner = BrowserStateInner {
        tabs: alloc::vec![home_tab],
        settings: BrowserSettings::default(),
        next_tab_id: 1,
    };

    {
        let mut guard = BROWSER_STATE.write();
        *guard = Some(inner);
    }

    ACTIVE_TAB_ID.store(0, Ordering::SeqCst);
    BROWSER_INITIALIZED.store(true, Ordering::SeqCst);
}

pub fn get_state() -> Option<BrowserState> {
    if !BROWSER_INITIALIZED.load(Ordering::SeqCst) {
        return None;
    }

    let guard = BROWSER_STATE.read();
    let inner = guard.as_ref()?;

    Some(BrowserState {
        tab_count: inner.tabs.len(),
        active_tab_id: ACTIVE_TAB_ID.load(Ordering::Relaxed),
        settings: inner.settings.clone(),
    })
}

pub fn is_initialized() -> bool {
    BROWSER_INITIALIZED.load(Ordering::SeqCst)
}

pub fn get_settings() -> BrowserSettings {
    let guard = BROWSER_STATE.read();
    match guard.as_ref() {
        Some(inner) => inner.settings.clone(),
        None => BrowserSettings::default(),
    }
}

pub fn update_settings(settings: BrowserSettings) {
    let mut guard = BROWSER_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.settings = settings;
    }
}

pub fn set_javascript_enabled(enabled: bool) {
    let mut guard = BROWSER_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.settings.javascript_enabled = enabled;
    }
}

pub fn set_cookies_enabled(enabled: bool) {
    let mut guard = BROWSER_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.settings.cookies_enabled = enabled;
    }
}

pub fn set_tracking_protection(enabled: bool) {
    let mut guard = BROWSER_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.settings.tracking_protection = enabled;
    }
}

pub fn set_fingerprint_protection(enabled: bool) {
    let mut guard = BROWSER_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.settings.fingerprint_protection = enabled;
    }
}

pub fn set_https_only(enabled: bool) {
    let mut guard = BROWSER_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.settings.https_only = enabled;
    }
}

pub fn set_proxy(config: ProxyConfig) {
    let mut guard = BROWSER_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.settings.proxy = config;
    }
}

pub fn allocate_tab_id() -> u32 {
    let mut guard = BROWSER_STATE.write();
    match guard.as_mut() {
        Some(inner) => {
            let id = inner.next_tab_id;
            inner.next_tab_id = inner.next_tab_id.wrapping_add(1);
            id
        }
        None => 0,
    }
}

pub fn add_tab(tab: BrowserTab) {
    let mut guard = BROWSER_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.tabs.push(tab);
    }
}

pub fn remove_tab(id: u32) -> bool {
    let mut guard = BROWSER_STATE.write();
    if let Some(inner) = guard.as_mut() {
        if let Some(pos) = inner.tabs.iter().position(|t| t.id == id) {
            inner.tabs.remove(pos);
            return true;
        }
    }
    false
}

pub fn get_tab(id: u32) -> Option<BrowserTab> {
    let guard = BROWSER_STATE.read();
    let inner = guard.as_ref()?;
    inner.tabs.iter().find(|t| t.id == id).cloned()
}

pub fn get_all_tabs() -> Vec<BrowserTab> {
    let guard = BROWSER_STATE.read();
    match guard.as_ref() {
        Some(inner) => inner.tabs.clone(),
        None => Vec::new(),
    }
}

pub fn update_tab<F>(id: u32, f: F)
where
    F: FnOnce(&mut BrowserTab),
{
    let mut guard = BROWSER_STATE.write();
    if let Some(inner) = guard.as_mut() {
        if let Some(tab) = inner.tabs.iter_mut().find(|t| t.id == id) {
            f(tab);
        }
    }
}

pub fn set_active_tab(id: u32) {
    ACTIVE_TAB_ID.store(id, Ordering::SeqCst);
}

pub fn get_active_tab_id() -> u32 {
    ACTIVE_TAB_ID.load(Ordering::Relaxed)
}

pub fn shutdown() {
    let mut guard = BROWSER_STATE.write();
    *guard = None;
    drop(guard);

    ACTIVE_TAB_ID.store(0, Ordering::SeqCst);
    BROWSER_INITIALIZED.store(false, Ordering::SeqCst);
}
