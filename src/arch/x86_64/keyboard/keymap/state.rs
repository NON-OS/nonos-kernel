// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::{AtomicU8, Ordering};

use crate::arch::x86_64::keyboard::types::Modifiers;

static GLOBAL_MODIFIERS: AtomicU8 = AtomicU8::new(0);

pub fn get_modifiers() -> Modifiers {
    Modifiers::from_bits(GLOBAL_MODIFIERS.load(Ordering::Acquire))
}

pub fn set_modifiers(mods: Modifiers) {
    GLOBAL_MODIFIERS.store(mods.bits(), Ordering::Release);
}

pub fn reset_modifiers() {
    GLOBAL_MODIFIERS.store(0, Ordering::Release);
}

pub fn update_modifiers(scan_code: u8, is_release: bool, is_extended: bool) {
    let current = GLOBAL_MODIFIERS.load(Ordering::Acquire);
    let mut mods = Modifiers::from_bits(current);

    if is_extended {
        match scan_code {
            0x1D => {
                if is_release {
                    mods.clear(Modifiers::CTRL);
                } else {
                    mods.set(Modifiers::CTRL);
                }
            }
            0x38 => {
                if is_release {
                    mods.clear(Modifiers::ALTGR);
                } else {
                    mods.set(Modifiers::ALTGR);
                }
            }
            _ => {}
        }
    } else {
        match scan_code {
            0x2A | 0x36 => {
                if is_release {
                    mods.clear(Modifiers::SHIFT);
                } else {
                    mods.set(Modifiers::SHIFT);
                }
            }
            0x1D => {
                if is_release {
                    mods.clear(Modifiers::CTRL);
                } else {
                    mods.set(Modifiers::CTRL);
                }
            }
            0x38 => {
                if is_release {
                    mods.clear(Modifiers::ALT);
                } else {
                    mods.set(Modifiers::ALT);
                }
            }
            0x3A => {
                if !is_release {
                    mods.toggle(Modifiers::CAPS_LOCK);
                }
            }
            0x45 => {
                if !is_release {
                    mods.toggle(Modifiers::NUM_LOCK);
                }
            }
            0x46 => {
                if !is_release {
                    mods.toggle(Modifiers::SCROLL_LOCK);
                }
            }
            _ => {}
        }
    }

    GLOBAL_MODIFIERS.store(mods.bits(), Ordering::Release);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedState {
    None,
    E0Pending,
    E1Pending(u8),
}

const EXT_NONE: u8 = 0;
const EXT_E0: u8 = 1;
const EXT_E1_1: u8 = 2;
const EXT_E1_2: u8 = 3;

static EXTENDED_STATE: AtomicU8 = AtomicU8::new(0);

pub fn get_extended_state() -> ExtendedState {
    match EXTENDED_STATE.load(Ordering::Acquire) {
        EXT_E0 => ExtendedState::E0Pending,
        EXT_E1_1 => ExtendedState::E1Pending(1),
        EXT_E1_2 => ExtendedState::E1Pending(2),
        _ => ExtendedState::None,
    }
}

pub fn set_extended_state(state: ExtendedState) {
    let val = match state {
        ExtendedState::None => EXT_NONE,
        ExtendedState::E0Pending => EXT_E0,
        ExtendedState::E1Pending(1) => EXT_E1_1,
        ExtendedState::E1Pending(_) => EXT_E1_2,
    };
    EXTENDED_STATE.store(val, Ordering::Release);
}

pub fn reset_extended_state() {
    EXTENDED_STATE.store(EXT_NONE, Ordering::Release);
}
