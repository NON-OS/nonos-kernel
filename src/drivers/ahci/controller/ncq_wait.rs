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

use super::super::constants::{IS_TFES, PORT_IS, PORT_SACT, PORT_TFD};
use super::super::error::AhciError;
use super::helpers::RegisterAccess;
use super::io::reset_port_on_error;
use core::sync::atomic::{AtomicU64, Ordering};

pub(super) fn wait_ncq_complete<T: RegisterAccess>(
    ctrl: &T,
    errors: &AtomicU64,
    port_resets: &AtomicU64,
    timeout: u32,
    port: u32,
    tag: u32,
) -> Result<(), AhciError> {
    let mut remaining = timeout;
    loop {
        let sact = ctrl.read_port_reg(port, PORT_SACT);
        let is = ctrl.read_port_reg(port, PORT_IS);
        let tfd = ctrl.read_port_reg(port, PORT_TFD);
        if (sact & (1 << tag)) == 0 {
            ctrl.write_port_reg(port, PORT_IS, is);
            if (is & IS_TFES) != 0 || (tfd & 0x01) != 0 {
                errors.fetch_add(1, Ordering::Relaxed);
                let _ = reset_port_on_error(ctrl, port_resets, port);
                return Err(AhciError::CommandFailed);
            }
            return Ok(());
        }
        if (is & IS_TFES) != 0 {
            ctrl.write_port_reg(port, PORT_IS, is);
            errors.fetch_add(1, Ordering::Relaxed);
            let _ = reset_port_on_error(ctrl, port_resets, port);
            return Err(AhciError::CommandFailed);
        }
        if remaining == 0 {
            errors.fetch_add(1, Ordering::Relaxed);
            let _ = reset_port_on_error(ctrl, port_resets, port);
            return Err(AhciError::CommandTimeout);
        }
        remaining -= 1;
    }
}
