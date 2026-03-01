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

use alloc::boxed::Box;
use spin::Mutex;

use crate::drivers::pci;

use super::constants::{HDA_CLASS, HDA_SUBCLASS};
use super::controller::HdAudioController;
use super::error::AudioError;

static HDA_ONCE: spin::Once<&'static Mutex<HdAudioController>> = spin::Once::new();

pub fn init_hd_audio() -> Result<(), AudioError> {
    if HDA_ONCE.is_completed() {
        return Ok(());
    }

    let dev = pci::scan_and_collect()
        .into_iter()
        .find(|d| d.class == HDA_CLASS && d.subclass == HDA_SUBCLASS)
        .ok_or(AudioError::NoControllerFound)?;

    let controller = HdAudioController::new(&dev)?;
    let boxed = Box::leak(Box::new(Mutex::new(controller)));
    HDA_ONCE.call_once(|| boxed);

    crate::log::logger::log_critical("HD Audio subsystem initialized");
    Ok(())
}

#[inline]
pub fn get_controller() -> Option<spin::MutexGuard<'static, HdAudioController>> {
    HDA_ONCE.get().map(|m| m.lock())
}

#[inline]
pub fn is_initialized() -> bool {
    HDA_ONCE.is_completed()
}
