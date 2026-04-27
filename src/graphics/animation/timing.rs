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

use core::sync::atomic::{AtomicU64, Ordering};

static FRAME_TIME: AtomicU64 = AtomicU64::new(0);
static LAST_FRAME_TIME: AtomicU64 = AtomicU64::new(0);
static DELTA_TIME: AtomicU64 = AtomicU64::new(16);
static FRAME_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn update_frame_time(current_ms: u64) {
    let last = FRAME_TIME.swap(current_ms, Ordering::SeqCst);
    LAST_FRAME_TIME.store(last, Ordering::SeqCst);
    let delta = if current_ms > last { current_ms - last } else { 16 };
    DELTA_TIME.store(delta.min(100), Ordering::SeqCst);
    FRAME_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn current_time() -> u64 {
    FRAME_TIME.load(Ordering::Relaxed)
}
pub fn delta_time() -> u64 {
    DELTA_TIME.load(Ordering::Relaxed)
}
pub fn frame_count() -> u64 {
    FRAME_COUNT.load(Ordering::Relaxed)
}

pub fn delta_seconds() -> f32 {
    delta_time() as f32 / 1000.0
}
pub fn fps() -> u32 {
    let dt = delta_time();
    if dt > 0 {
        (1000 / dt) as u32
    } else {
        60
    }
}

pub fn should_update_animation(last_update: u64, interval_ms: u64) -> bool {
    current_time().saturating_sub(last_update) >= interval_ms
}

pub fn ms_to_frames(ms: u64, target_fps: u32) -> u32 {
    ((ms * target_fps as u64) / 1000) as u32
}

pub fn frames_to_ms(frames: u32, target_fps: u32) -> u64 {
    (frames as u64 * 1000) / target_fps as u64
}

pub const TARGET_FPS: u32 = 60;
pub const FRAME_BUDGET_MS: u64 = 16;
