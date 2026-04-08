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

use core::sync::atomic::Ordering;
use super::super::error::{Ps2Error, Ps2Result};
use super::super::types::LedState;
use super::keyboard::TypematicConfig;
use super::globals::{INITIALIZED, CONTROLLER, KEYBOARD, MOUSE};

pub fn init() -> Ps2Result<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) { return Err(Ps2Error::AlreadyInitialized); }
    let mut ctrl = CONTROLLER.lock();
    ctrl.init()?;
    { let mut kb = KEYBOARD.lock(); if let Err(e) = kb.init(&ctrl) { if !ctrl.port2_working() { INITIALIZED.store(false, Ordering::SeqCst); return Err(e); } } }
    if ctrl.port2_working() { let mut m = MOUSE.lock(); let _ = m.init(&ctrl); }
    Ok(())
}

pub fn is_initialized() -> bool { INITIALIZED.load(Ordering::Acquire) }
pub fn has_keyboard() -> bool { KEYBOARD.lock().is_detected() }
pub fn has_mouse() -> bool { MOUSE.lock().is_detected() }

pub fn set_leds(leds: LedState) -> Ps2Result<()> {
    if !is_initialized() { return Err(Ps2Error::NotInitialized); }
    let ctrl = CONTROLLER.lock();
    KEYBOARD.lock().set_leds(&ctrl, leds)
}

pub fn set_typematic(config: TypematicConfig) -> Ps2Result<()> {
    if !is_initialized() { return Err(Ps2Error::NotInitialized); }
    let ctrl = CONTROLLER.lock();
    KEYBOARD.lock().set_typematic(&ctrl, config)
}
