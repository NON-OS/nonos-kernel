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

//! Theme palette held in lock-free atomics. Each colour and the
//! revision counter are independently updated; readers see a
//! consistent palette because every word is loaded with `Acquire`.

use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy)]
pub struct Theme {
    pub background_argb: u32,
    pub surface_argb: u32,
    pub accent_argb: u32,
    pub text_argb: u32,
    pub border_argb: u32,
    pub revision: u32,
}

static BG: AtomicU32 = AtomicU32::new(0xFF10_1620);
static SURFACE: AtomicU32 = AtomicU32::new(0xFF1A_2030);
static ACCENT: AtomicU32 = AtomicU32::new(0xFF66_FFFF);
static TEXT: AtomicU32 = AtomicU32::new(0xFFF4_F4F4);
static BORDER: AtomicU32 = AtomicU32::new(0xFF2E_5C5C);
static REVISION: AtomicU32 = AtomicU32::new(1);

pub fn snapshot() -> Theme {
    Theme {
        background_argb: BG.load(Ordering::Acquire),
        surface_argb: SURFACE.load(Ordering::Acquire),
        accent_argb: ACCENT.load(Ordering::Acquire),
        text_argb: TEXT.load(Ordering::Acquire),
        border_argb: BORDER.load(Ordering::Acquire),
        revision: REVISION.load(Ordering::Acquire),
    }
}

pub fn replace(new: Theme) {
    BG.store(new.background_argb, Ordering::Release);
    SURFACE.store(new.surface_argb, Ordering::Release);
    ACCENT.store(new.accent_argb, Ordering::Release);
    TEXT.store(new.text_argb, Ordering::Release);
    BORDER.store(new.border_argb, Ordering::Release);
    REVISION.fetch_add(1, Ordering::AcqRel);
}
