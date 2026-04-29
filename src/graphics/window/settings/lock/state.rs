// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Lock screen settings state - real settings for lock screen behavior.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static REQUIRE_WALLET: AtomicBool = AtomicBool::new(true);
static LOCK_AFTER_SLEEP: AtomicBool = AtomicBool::new(true);
static LOCK_TIMEOUT_IDX: AtomicU8 = AtomicU8::new(2);
static SHOW_MESSAGE: AtomicBool = AtomicBool::new(false);
static AUTO_LOGIN: AtomicBool = AtomicBool::new(false);
static SCREENSAVER_IDX: AtomicU8 = AtomicU8::new(0);
static SCREENSAVER_TIMEOUT_IDX: AtomicU8 = AtomicU8::new(2);

pub(super) static LOCK_TIMEOUTS: &[(&str, u32)] = &[
    ("Immediately", 0),
    ("1 minute", 60),
    ("5 minutes", 300),
    ("15 minutes", 900),
    ("1 hour", 3600),
    ("Never", u32::MAX),
];

pub(super) static SCREENSAVERS: &[&str] =
    &["None", "Floating Clock", "Matrix", "Starfield", "Blank"];

#[derive(Clone, Copy)]
pub struct LockState {
    pub require_wallet: bool,
    pub lock_after_sleep: bool,
    pub lock_timeout_idx: u8,
    pub show_message: bool,
    pub auto_login: bool,
    pub screensaver_idx: u8,
    pub screensaver_timeout_idx: u8,
}

impl LockState {
    pub fn lock_timeout_label(&self) -> &'static str {
        LOCK_TIMEOUTS.get(self.lock_timeout_idx as usize).map(|(s, _)| *s).unwrap_or("5 minutes")
    }
    pub fn screensaver_name(&self) -> &'static str {
        SCREENSAVERS.get(self.screensaver_idx as usize).copied().unwrap_or("None")
    }
    pub fn lock_timeout_seconds(&self) -> u32 {
        LOCK_TIMEOUTS.get(self.lock_timeout_idx as usize).map(|(_, s)| *s).unwrap_or(300)
    }
}

pub(super) fn get_state() -> LockState {
    LockState {
        require_wallet: REQUIRE_WALLET.load(Ordering::Relaxed),
        lock_after_sleep: LOCK_AFTER_SLEEP.load(Ordering::Relaxed),
        lock_timeout_idx: LOCK_TIMEOUT_IDX.load(Ordering::Relaxed),
        show_message: SHOW_MESSAGE.load(Ordering::Relaxed),
        auto_login: AUTO_LOGIN.load(Ordering::Relaxed),
        screensaver_idx: SCREENSAVER_IDX.load(Ordering::Relaxed),
        screensaver_timeout_idx: SCREENSAVER_TIMEOUT_IDX.load(Ordering::Relaxed),
    }
}

pub(super) fn set_require_wallet(v: bool) {
    REQUIRE_WALLET.store(v, Ordering::Relaxed);
}
pub(super) fn set_lock_after_sleep(v: bool) {
    LOCK_AFTER_SLEEP.store(v, Ordering::Relaxed);
}
pub(super) fn set_lock_timeout(idx: u8) {
    LOCK_TIMEOUT_IDX.store(idx.min(5), Ordering::Relaxed);
}
pub(super) fn set_show_message(v: bool) {
    SHOW_MESSAGE.store(v, Ordering::Relaxed);
}
pub(super) fn set_auto_login(v: bool) {
    AUTO_LOGIN.store(v, Ordering::Relaxed);
}
pub(super) fn set_screensaver(idx: u8) {
    SCREENSAVER_IDX.store(idx.min(4), Ordering::Relaxed);
}
pub(super) fn set_screensaver_timeout(idx: u8) {
    SCREENSAVER_TIMEOUT_IDX.store(idx.min(5), Ordering::Relaxed);
}

// ============ Public API for Lock Subsystem ============

/// Check if wallet authentication is required to unlock
pub(super) fn requires_wallet() -> bool {
    REQUIRE_WALLET.load(Ordering::Relaxed)
}

/// Check if screen should lock after sleep/wake
pub(super) fn should_lock_after_sleep() -> bool {
    LOCK_AFTER_SLEEP.load(Ordering::Relaxed)
}

/// Get lock timeout in seconds (0 = immediate, MAX = never)
pub(super) fn lock_timeout_seconds() -> u32 {
    LOCK_TIMEOUTS
        .get(LOCK_TIMEOUT_IDX.load(Ordering::Relaxed) as usize)
        .map(|(_, s)| *s)
        .unwrap_or(300)
}

/// Get active screensaver index
pub(super) fn active_screensaver() -> u8 {
    SCREENSAVER_IDX.load(Ordering::Relaxed)
}

/// Get screensaver timeout in seconds
pub(super) fn screensaver_timeout_seconds() -> u32 {
    LOCK_TIMEOUTS
        .get(SCREENSAVER_TIMEOUT_IDX.load(Ordering::Relaxed) as usize)
        .map(|(_, s)| *s)
        .unwrap_or(300)
}

/// Check if auto-login is enabled (bypasses wallet auth on boot)
pub(super) fn is_auto_login() -> bool {
    AUTO_LOGIN.load(Ordering::Relaxed)
}
