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

//! Following the theme chosen in the policy store: read at most once a second,
//! and taken into this process's theme store when it changes.

use core::sync::atomic::{AtomicI64, AtomicU32, Ordering};

use nonos_libc::mk_uptime_ms;
use nonos_policy_client::{get_bool, get_u8, lookup};
use nonos_policy_proto::Field;
use nonos_toolkit::theme::{store, theme_of};

/// The shortest gap between two reads of the policy store, in milliseconds.
const CHECK_EVERY_MS: i64 = 1000;

/// Set in `APPLIED` once a choice has been applied.
const APPLIED_BIT: u32 = 1 << 31;

/// When the store was last read; `i64::MIN` until the first check.
static LAST_CHECK_MS: AtomicI64 = AtomicI64::new(i64::MIN);

/// The policy store's port; 0 while it has not been looked up.
static PORT: AtomicU32 = AtomicU32::new(0);

/// The applied choice: index in bits 0-7, high contrast in bit 8, `APPLIED_BIT`.
static APPLIED: AtomicU32 = AtomicU32::new(0);

/// Read the chosen theme once a second has passed since the last read and take
/// it when it differs from the applied one. True when the theme changed.
pub fn follow() -> bool {
    let now = mk_uptime_ms();
    let last = LAST_CHECK_MS.load(Ordering::Relaxed);
    if last != i64::MIN && (0..CHECK_EVERY_MS).contains(&now.saturating_sub(last)) {
        return false;
    }
    LAST_CHECK_MS.store(now, Ordering::Relaxed);
    let Some(port) = port() else { return false };
    let Some(index) = get_u8(port, Field::Theme) else {
        PORT.store(0, Ordering::Relaxed);
        return false;
    };
    let high_contrast = get_bool(port, Field::HighContrast).unwrap_or(false);
    let choice = APPLIED_BIT | (u32::from(high_contrast) << 8) | u32::from(index);
    if APPLIED.load(Ordering::Relaxed) == choice {
        return false;
    }
    store::replace(theme_of(index, high_contrast));
    APPLIED.store(choice, Ordering::Relaxed);
    true
}

/// The cached policy port, looked up and cached when there is none yet.
fn port() -> Option<u32> {
    let cached = PORT.load(Ordering::Relaxed);
    if cached != 0 {
        return Some(cached);
    }
    let port = lookup()?;
    PORT.store(port, Ordering::Relaxed);
    Some(port)
}
