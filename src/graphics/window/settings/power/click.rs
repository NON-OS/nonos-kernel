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

use super::state::{set_reboot, set_shutdown};

pub(crate) fn handle_click(cx: u32, cy: u32, _cw: u32, mx: i32, my: i32) -> bool {
    let shutdown_x = cx + 28;
    let shutdown_y = cy + 138;
    if mx >= shutdown_x as i32 && mx < (shutdown_x + 120) as i32 {
        if my >= shutdown_y as i32 && my < (shutdown_y + 24) as i32 {
            set_shutdown();
            return true;
        }
    }
    let reboot_x = cx + 156;
    let reboot_y = cy + 138;
    if mx >= reboot_x as i32 && mx < (reboot_x + 100) as i32 {
        if my >= reboot_y as i32 && my < (reboot_y + 24) as i32 {
            set_reboot();
            return true;
        }
    }
    false
}
