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

use core::sync::atomic::{AtomicU32, Ordering};

static CODECS_DISCOVERED: AtomicU32 = AtomicU32::new(0);
static PATHS_DISCOVERED: AtomicU32 = AtomicU32::new(0);
static QUIRKS_APPLIED: AtomicU32 = AtomicU32::new(0);

pub fn codec_stats() -> (u32, u32, u32) {
    (
        CODECS_DISCOVERED.load(Ordering::Relaxed),
        PATHS_DISCOVERED.load(Ordering::Relaxed),
        QUIRKS_APPLIED.load(Ordering::Relaxed),
    )
}

pub(super) fn increment_codecs_discovered() {
    CODECS_DISCOVERED.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn increment_paths_discovered(count: u32) {
    PATHS_DISCOVERED.fetch_add(count, Ordering::Relaxed);
}

pub(super) fn increment_quirks_applied() {
    QUIRKS_APPLIED.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
pub fn reset_codec_stats() {
    CODECS_DISCOVERED.store(0, Ordering::Relaxed);
    PATHS_DISCOVERED.store(0, Ordering::Relaxed);
    QUIRKS_APPLIED.store(0, Ordering::Relaxed);
}
