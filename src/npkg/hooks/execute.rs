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
use super::{cmd_file, cmd_link, cmd_misc, cmd_mkdir, cmd_perms, cmd_rm};
use crate::npkg::error::{NpkgError, NpkgResult};
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn execute_script(package: &str, script: &str, hook_type: &str) -> NpkgResult<()> {
    let mut env = ScriptEnv::new(package);
    for line in script.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Err(e) = execute_line(&mut env, line) {
            crate::warn!("npkg: {} script error: {}", hook_type, e);
            return Err(NpkgError::HookFailed(alloc::format!("{}: {}", hook_type, e)));
        }
    }
    Ok(())
}

pub(super) fn execute_line(env: &mut ScriptEnv, line: &str) -> Result<(), String> {
    let line = env.expand_variables(line);
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }
    let cmd = parts[0];
    let args = &parts[1..];
    match cmd {
        "mkdir" => cmd_mkdir::cmd_mkdir(args),
        "rmdir" => cmd_rm::cmd_rmdir(args),
        "rm" => cmd_rm::cmd_rm(args),
        "cp" => cmd_file::cmd_cp(args),
        "mv" => cmd_file::cmd_mv(args),
        "ln" => cmd_link::cmd_ln(args),
        "chmod" => cmd_perms::cmd_chmod(args),
        "chown" => cmd_perms::cmd_chown(args),
        "touch" => cmd_file::cmd_touch(args),
        "echo" => cmd_misc::cmd_echo(args),
        "set" => cmd_misc::cmd_set(env, args),
        "ldconfig" => cmd_misc::cmd_ldconfig(),
        "update-desktop-database" => cmd_misc::cmd_update_desktop(),
        "update-mime-database" => cmd_misc::cmd_update_mime(),
        "fc-cache" => cmd_misc::cmd_fc_cache(),
        "systemctl" => cmd_misc::cmd_systemctl(args),
        _ => {
            crate::warn!("npkg: unknown script command: {}", cmd);
            Ok(())
        }
    }
}
