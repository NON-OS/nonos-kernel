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
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use spin::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EcosystemTab {
    Browser = 0,
    Wallet = 1,
    Staking = 2,
    Liquidity = 3,
    Node = 4,
    Privacy = 5,
}

impl EcosystemTab {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Browser,
            1 => Self::Wallet,
            2 => Self::Staking,
            3 => Self::Liquidity,
            4 => Self::Node,
            5 => Self::Privacy,
            _ => Self::Browser,
        }
    }

    pub fn label(&self) -> &'static [u8] {
        match self {
            Self::Browser => b"Browser",
            Self::Wallet => b"Wallet",
            Self::Staking => b"Staking",
            Self::Liquidity => b"LP",
            Self::Node => b"Node",
            Self::Privacy => b"Privacy",
        }
    }

    pub fn count() -> usize {
        6
    }
}

pub static ACTIVE_TAB: AtomicU8 = AtomicU8::new(0);

pub fn get_active_tab() -> EcosystemTab {
    EcosystemTab::from_u8(ACTIVE_TAB.load(Ordering::Relaxed))
}

pub fn set_active_tab(tab: EcosystemTab) {
    ACTIVE_TAB.store(tab as u8, Ordering::Relaxed);
}

pub static INPUT_FOCUSED: AtomicBool = AtomicBool::new(false);

pub fn is_input_focused() -> bool {
    INPUT_FOCUSED.load(Ordering::Relaxed)
}

pub fn set_input_focused(focused: bool) {
    INPUT_FOCUSED.store(focused, Ordering::Relaxed);
}

pub const MAX_URL_LEN: usize = 2048;
pub const MAX_INPUT_LEN: usize = 256;

pub static URL_BUFFER: Mutex<[u8; MAX_URL_LEN]> = Mutex::new([0u8; MAX_URL_LEN]);
pub static URL_LEN: AtomicUsize = AtomicUsize::new(0);
pub static URL_CURSOR: AtomicUsize = AtomicUsize::new(0);
pub static URL_FOCUSED: AtomicBool = AtomicBool::new(true);

pub static INPUT_BUFFER: Mutex<[u8; MAX_INPUT_LEN]> = Mutex::new([0u8; MAX_INPUT_LEN]);
pub static INPUT_LEN: AtomicUsize = AtomicUsize::new(0);
pub static INPUT_CURSOR: AtomicUsize = AtomicUsize::new(0);

pub static LOADING: AtomicBool = AtomicBool::new(false);
pub static IS_HTTPS: AtomicBool = AtomicBool::new(false);
pub static CERT_VERIFIED: AtomicBool = AtomicBool::new(false);
pub static ERROR_MSG: Mutex<[u8; 128]> = Mutex::new([0u8; 128]);
pub static ERROR_LEN: AtomicUsize = AtomicUsize::new(0);

pub static PAGE_CONTENT: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub static PAGE_SCROLL: AtomicUsize = AtomicUsize::new(0);
pub static PAGE_TITLE: Mutex<[u8; 128]> = Mutex::new([0u8; 128]);
pub static PAGE_TITLE_LEN: AtomicUsize = AtomicUsize::new(0);
pub static CONTENT_CHANGED: AtomicBool = AtomicBool::new(false);
pub static PAGE_TOTAL_LINES: AtomicUsize = AtomicUsize::new(0);

pub fn mark_content_changed() {
    CONTENT_CHANGED.store(true, Ordering::Relaxed);
}

pub fn take_content_changed() -> bool {
    CONTENT_CHANGED.swap(false, Ordering::Relaxed)
}

pub static WALLET_CONNECTED: AtomicBool = AtomicBool::new(false);
pub static WALLET_ADDRESS: Mutex<[u8; 42]> = Mutex::new([0u8; 42]);
pub static WALLET_BALANCE: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
pub static WALLET_BALANCE_LEN: AtomicUsize = AtomicUsize::new(0);

pub static STAKING_AMOUNT: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
pub static STAKING_AMOUNT_LEN: AtomicUsize = AtomicUsize::new(0);
pub static STAKING_REWARDS: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
pub static STAKING_REWARDS_LEN: AtomicUsize = AtomicUsize::new(0);

pub static LP_TOTAL_VALUE: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
pub static LP_TOTAL_VALUE_LEN: AtomicUsize = AtomicUsize::new(0);
pub static LP_APY: Mutex<[u8; 16]> = Mutex::new([0u8; 16]);
pub static LP_APY_LEN: AtomicUsize = AtomicUsize::new(0);

pub static NODE_CONNECTED: AtomicBool = AtomicBool::new(false);
pub static NODE_PEERS: AtomicUsize = AtomicUsize::new(0);
pub static NODE_BLOCK_HEIGHT: AtomicUsize = AtomicUsize::new(0);
pub static NODE_SYNC_PROGRESS: AtomicU8 = AtomicU8::new(0);

pub static PRIVACY_TRACKERS_BLOCKED: AtomicUsize = AtomicUsize::new(0);
pub static PRIVACY_ADS_BLOCKED: AtomicUsize = AtomicUsize::new(0);
pub static PRIVACY_URLS_CLEANED: AtomicUsize = AtomicUsize::new(0);

pub fn get_url_string() -> Option<String> {
    let buf = URL_BUFFER.lock();
    let len = URL_LEN.load(Ordering::Relaxed);
    if len > 0 {
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else {
        None
    }
}

pub fn set_url(url: &str) {
    let mut buf = URL_BUFFER.lock();
    let len = url.len().min(MAX_URL_LEN - 1);
    buf[..len].copy_from_slice(&url.as_bytes()[..len]);
    URL_LEN.store(len, Ordering::Relaxed);
    URL_CURSOR.store(len, Ordering::Relaxed);
}

pub fn clear_url() {
    URL_LEN.store(0, Ordering::Relaxed);
    URL_CURSOR.store(0, Ordering::Relaxed);
}

pub fn set_error(msg: &str) {
    let mut buf = ERROR_MSG.lock();
    let len = msg.len().min(127);
    buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
    ERROR_LEN.store(len, Ordering::Relaxed);
}

pub fn clear_error() {
    ERROR_LEN.store(0, Ordering::Relaxed);
}

pub fn get_error() -> Option<String> {
    let len = ERROR_LEN.load(Ordering::Relaxed);
    if len > 0 {
        let buf = ERROR_MSG.lock();
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else {
        None
    }
}

pub fn set_wallet_address(addr: &str) {
    let mut buf = WALLET_ADDRESS.lock();
    let len = addr.len().min(42);
    buf[..len].copy_from_slice(&addr.as_bytes()[..len]);
    WALLET_CONNECTED.store(true, Ordering::Relaxed);
}

pub fn get_wallet_address() -> Option<String> {
    if !WALLET_CONNECTED.load(Ordering::Relaxed) {
        return None;
    }
    let buf = WALLET_ADDRESS.lock();
    core::str::from_utf8(&buf[..42]).ok().map(String::from)
}

pub fn set_wallet_balance(balance: &str) {
    let mut buf = WALLET_BALANCE.lock();
    let len = balance.len().min(31);
    buf[..len].copy_from_slice(&balance.as_bytes()[..len]);
    WALLET_BALANCE_LEN.store(len, Ordering::Relaxed);
}

pub fn get_wallet_balance() -> Option<String> {
    let len = WALLET_BALANCE_LEN.load(Ordering::Relaxed);
    if len > 0 {
        let buf = WALLET_BALANCE.lock();
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else {
        None
    }
}

pub fn set_staking_amount(amount: &str) {
    let mut buf = STAKING_AMOUNT.lock();
    let len = amount.len().min(31);
    buf[..len].copy_from_slice(&amount.as_bytes()[..len]);
    STAKING_AMOUNT_LEN.store(len, Ordering::Relaxed);
}

pub fn get_staking_amount() -> Option<String> {
    let len = STAKING_AMOUNT_LEN.load(Ordering::Relaxed);
    if len > 0 {
        let buf = STAKING_AMOUNT.lock();
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else {
        None
    }
}

pub fn set_staking_rewards(rewards: &str) {
    let mut buf = STAKING_REWARDS.lock();
    let len = rewards.len().min(31);
    buf[..len].copy_from_slice(&rewards.as_bytes()[..len]);
    STAKING_REWARDS_LEN.store(len, Ordering::Relaxed);
}

pub fn get_staking_rewards() -> Option<String> {
    let len = STAKING_REWARDS_LEN.load(Ordering::Relaxed);
    if len > 0 {
        let buf = STAKING_REWARDS.lock();
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else {
        None
    }
}

pub fn increment_trackers_blocked() {
    PRIVACY_TRACKERS_BLOCKED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_ads_blocked() {
    PRIVACY_ADS_BLOCKED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_urls_cleaned() {
    PRIVACY_URLS_CLEANED.fetch_add(1, Ordering::Relaxed);
}

pub fn set_page_title(title: &str) {
    let mut buf = PAGE_TITLE.lock();
    let len = title.len().min(127);
    buf[..len].copy_from_slice(&title.as_bytes()[..len]);
    PAGE_TITLE_LEN.store(len, Ordering::Relaxed);
}

pub fn get_page_title() -> Option<String> {
    let len = PAGE_TITLE_LEN.load(Ordering::Relaxed);
    if len > 0 {
        let buf = PAGE_TITLE.lock();
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else {
        None
    }
}

pub fn scroll_up(lines: usize) {
    let current = PAGE_SCROLL.load(Ordering::Relaxed);
    PAGE_SCROLL.store(current.saturating_sub(lines), Ordering::Relaxed);
}

pub fn scroll_down(lines: usize) {
    let current = PAGE_SCROLL.load(Ordering::Relaxed);
    let total = PAGE_TOTAL_LINES.load(Ordering::Relaxed);
    let new_scroll = (current + lines).min(total.saturating_sub(1));
    PAGE_SCROLL.store(new_scroll, Ordering::Relaxed);
}

#[derive(Clone)]
pub struct PageLink {
    pub line: usize,
    pub start_x: u32,
    pub end_x: u32,
    pub url: String,
}

pub static PAGE_LINKS: Mutex<Vec<PageLink>> = Mutex::new(Vec::new());
pub static CURRENT_BASE_URL: Mutex<Option<String>> = Mutex::new(None);

pub fn set_base_url(url: &str) {
    *CURRENT_BASE_URL.lock() = Some(String::from(url));
}

pub fn get_base_url() -> Option<String> {
    CURRENT_BASE_URL.lock().clone()
}

pub fn clear_page_links() {
    PAGE_LINKS.lock().clear();
}

pub fn add_page_link(line: usize, start_x: u32, end_x: u32, url: &str) {
    PAGE_LINKS.lock().push(PageLink {
        line,
        start_x,
        end_x,
        url: String::from(url),
    });
}

pub fn find_link_at(line: usize, x: u32) -> Option<String> {
    let links = PAGE_LINKS.lock();
    for link in links.iter() {
        if link.line == line && x >= link.start_x && x < link.end_x {
            return Some(link.url.clone());
        }
    }
    None
}

pub fn resolve_relative_url(relative: &str, base: &str) -> String {
    if relative.starts_with("http://") || relative.starts_with("https://") {
        return String::from(relative);
    }

    if relative.starts_with("//") {
        if base.starts_with("https://") {
            return alloc::format!("https:{}", relative);
        } else {
            return alloc::format!("http:{}", relative);
        }
    }

    if let Some(scheme_end) = base.find("://") {
        let after_scheme = &base[scheme_end + 3..];
        let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let host = &after_scheme[..host_end];
        let scheme = &base[..scheme_end];

        if relative.starts_with('/') {
            return alloc::format!("{}://{}{}", scheme, host, relative);
        } else {
            let path = &after_scheme[host_end..];
            let dir = if let Some(last_slash) = path.rfind('/') {
                &path[..last_slash + 1]
            } else {
                "/"
            };
            return alloc::format!("{}://{}{}{}", scheme, host, dir, relative);
        }
    }

    String::from(relative)
}
