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

use super::super::super::constants::*;
use super::super::super::error::AudioError;
use super::super::helpers::{spin_until, spin_while, RegisterAccess};

pub(super) fn reset_controller<T: RegisterAccess>(ctrl: &T) -> Result<(), AudioError> {
    let mut gctl = ctrl.read_reg32(GCTL);
    gctl &= !GCTL_CRST;
    ctrl.write_reg32(GCTL, gctl);
    if !spin_while(|| (ctrl.read_reg32(GCTL) & GCTL_CRST) != 0, SPIN_TIMEOUT_DEFAULT) {
        return Err(AudioError::CrstClearTimeout);
    }
    for _ in 0..100 {
        core::hint::spin_loop();
    }
    let mut gctl = ctrl.read_reg32(GCTL);
    gctl |= GCTL_CRST;
    ctrl.write_reg32(GCTL, gctl);
    if !spin_until(|| (ctrl.read_reg32(GCTL) & GCTL_CRST) != 0, SPIN_TIMEOUT_DEFAULT) {
        return Err(AudioError::CrstSetTimeout);
    }
    for _ in 0..1000 {
        core::hint::spin_loop();
    }
    Ok(())
}
