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

use super::env::ScriptEnv;
use alloc::string::String;

pub(super) fn cmd_echo(args: &[&str]) -> Result<(), String> {
    let msg = args.join(" ");
    crate::info!("npkg: {}", msg);
    Ok(())
}

pub(super) fn cmd_set(env: &mut ScriptEnv, args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Ok(());
    }
    let name = args[0];
    let value = args[1..].join(" ");
    env.variables.insert(String::from(name), value);
    Ok(())
}

pub(super) fn cmd_ldconfig() -> Result<(), String> {
    crate::info!("npkg: updating library cache");
    Ok(())
}

pub(super) fn cmd_update_desktop() -> Result<(), String> {
    crate::info!("npkg: updating desktop database");
    Ok(())
}

pub(super) fn cmd_update_mime() -> Result<(), String> {
    crate::info!("npkg: updating MIME database");
    Ok(())
}

pub(super) fn cmd_fc_cache() -> Result<(), String> {
    crate::info!("npkg: updating font cache");
    Ok(())
}

pub(super) fn cmd_systemctl(args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Ok(());
    }
    let action = args[0];
    let service = args[1];
    crate::info!("npkg: {} service {}", action, service);
    Ok(())
}
