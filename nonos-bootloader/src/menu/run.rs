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

use uefi::prelude::*;

use super::input::{poll_input, KeyAction};
use super::render::{clear_menu_area, clear_screen, draw_logo, render_menu};
use super::types::{MenuAction, MenuState};

const POLL_INTERVAL_MS: u64 = 50;

pub fn run_boot_menu(bs: &BootServices, state: &mut MenuState) -> MenuAction {
    clear_screen();
    draw_logo();
    state.visible = true;
    state.elapsed_ms = 0;

    loop {
        render_menu(state);

        let action = poll_input(bs);
        match action {
            KeyAction::Up => {
                state.select_prev();
                state.elapsed_ms = 0;
            }
            KeyAction::Down => {
                state.select_next();
                state.elapsed_ms = 0;
            }
            KeyAction::Select => {
                state.visible = false;
                clear_menu_area();
                return state.current_action();
            }
            KeyAction::Cancel => {
                state.visible = false;
                clear_menu_area();
                return MenuAction::Continue;
            }
            KeyAction::None => {}
            KeyAction::ShowMenu => {
                state.elapsed_ms = 0;
            }
        }

        bs.stall(POLL_INTERVAL_MS as usize * 1000);
        state.elapsed_ms = state.elapsed_ms.saturating_add(POLL_INTERVAL_MS);

        if state.is_timed_out() {
            state.visible = false;
            clear_menu_area();
            return MenuAction::Timeout;
        }
    }
}
