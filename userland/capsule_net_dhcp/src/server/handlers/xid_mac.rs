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

use crate::state::STATE;

// Pull the current (l2_port, ip_port, mac) trio in one shot.
// Returns `None` if `setup::run` has not yet completed — the
// caller responds with `E_NO_LINK`.
pub fn current() -> Option<(u32, u32, [u8; 6])> {
    let l2 = STATE.l2();
    let ip = STATE.ip();
    if l2 == 0 || ip == 0 {
        return None;
    }
    let mac = *STATE.mac.lock();
    if mac == [0; 6] {
        return None;
    }
    Some((l2, ip, mac))
}
