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

use super::constants::*;
use crate::graphics::window::state::TITLE_BAR_HEIGHT;
use crate::process::get_all_processes;

pub(crate) fn handle_click(wx: u32, wy: u32, ww: u32, _wh: u32, cx: i32, cy: i32) -> bool {
    let content_y = wy + TITLE_BAR_HEIGHT;
    if cx >= (wx + ww - 80) as i32
        && cx < (wx + ww - 10) as i32
        && cy >= content_y as i32 + 5
        && cy <= content_y as i32 + 30
    {
        return true;
    }
    let rows_start = content_y + HEADER_HEIGHT + TABLE_HEADER_HEIGHT + 4;
    if cy >= rows_start as i32 {
        let row = ((cy - rows_start as i32) / ROW_HEIGHT as i32) as usize;
        let processes = get_all_processes();
        if row < processes.len() {
            let kill_x = (wx + ww - 70) as i32;
            if cx >= kill_x && cx < kill_x + 55 {
                let proc = &processes[row];
                let can = proc.pid > 1 && !matches!(proc.name.as_str(), "kernel" | "init");
                if can {
                    proc.terminate_with_signal(9);
                    return true;
                }
            }
        }
    }
    false
}
