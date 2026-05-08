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
use nonos_boot::menu::{run_boot_menu, MenuState, SecurityMode};
use super::action::resolve_action;

pub fn select_security_mode(st: &mut SystemTable<Boot>, dev_override: bool) -> Result<SecurityMode, Status> {
    if dev_override {
        let _ = st.stdout().output_string(uefi::cstr16!("[WARN] DEV MODE - SECURITY BYPASSED\r\n"));
        return Ok(SecurityMode::Development);
    }
    let mut menu_state = MenuState::default();
    let menu_action = run_boot_menu(st.boot_services(), &mut menu_state);
    resolve_action(st, menu_action)
}
