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

use alloc::string::String;
use alloc::vec::Vec;
use super::error::{NpkgError, NpkgResult};

#[derive(Debug, Clone)]
pub struct PreInstallHook {
    pub package: String,
    pub version: String,
    pub script: String,
}

#[derive(Debug, Clone)]
pub struct PostInstallHook {
    pub package: String,
    pub version: String,
    pub script: String,
    pub files_installed: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PreRemoveHook {
    pub package: String,
    pub version: String,
    pub script: String,
    pub files: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PostRemoveHook {
    pub package: String,
    pub version: String,
    pub script: String,
}

pub fn run_pre_install(package: &str, script: &str) -> NpkgResult<()> {
    if script.is_empty() {
        return Ok(());
    }

    crate::info!("npkg: running pre-install script for {}", package);

    execute_script(package, script, "pre_install")
}

pub fn run_post_install(package: &str, script: &str) -> NpkgResult<()> {
    if script.is_empty() {
        return Ok(());
    }

    crate::info!("npkg: running post-install script for {}", package);

    execute_script(package, script, "post_install")
}

pub fn run_pre_remove(package: &str, script: &str) -> NpkgResult<()> {
    if script.is_empty() {
        return Ok(());
    }

    crate::info!("npkg: running pre-remove script for {}", package);

    execute_script(package, script, "pre_remove")
}

pub fn run_post_remove(package: &str, script: &str) -> NpkgResult<()> {
    if script.is_empty() {
        return Ok(());
    }

    crate::info!("npkg: running post-remove script for {}", package);

    execute_script(package, script, "post_remove")
}

fn execute_script(package: &str, script: &str, hook_type: &str) -> NpkgResult<()> {
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

struct ScriptEnv {
    variables: alloc::collections::BTreeMap<String, String>,
}

impl ScriptEnv {
    fn new(package: &str) -> Self {
        let mut variables = alloc::collections::BTreeMap::new();
        variables.insert(String::from("PKG_NAME"), String::from(package));
        variables.insert(String::from("PKG_ROOT"), String::from("/"));

        Self {
            variables,
        }
    }

    fn expand_variables(&self, s: &str) -> String {
        let mut result = String::from(s);

        for (key, value) in &self.variables {
            let pattern = alloc::format!("${{{}}}", key);
            result = result.replace(&pattern, value);

            let pattern2 = alloc::format!("${}", key);
            result = result.replace(&pattern2, value);
        }

        result
    }
}

fn execute_line(env: &mut ScriptEnv, line: &str) -> Result<(), String> {
    let line = env.expand_variables(line);
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.is_empty() {
        return Ok(());
    }

    let cmd = parts[0];
    let args = &parts[1..];

    match cmd {
        "mkdir" => cmd_mkdir(args),
        "rmdir" => cmd_rmdir(args),
        "rm" => cmd_rm(args),
        "cp" => cmd_cp(args),
        "mv" => cmd_mv(args),
        "ln" => cmd_ln(args),
        "chmod" => cmd_chmod(args),
        "chown" => cmd_chown(args),
        "touch" => cmd_touch(args),
        "echo" => cmd_echo(args),
        "set" => cmd_set(env, args),
        "ldconfig" => cmd_ldconfig(),
        "update-desktop-database" => cmd_update_desktop(),
        "update-mime-database" => cmd_update_mime(),
        "fc-cache" => cmd_fc_cache(),
        "systemctl" => cmd_systemctl(args),
        _ => {
            crate::warn!("npkg: unknown script command: {}", cmd);
            Ok(())
        }
    }
}

fn cmd_mkdir(args: &[&str]) -> Result<(), String> {
    let mut parents = false;
    let mut mode = 0o755u32;
    let mut paths = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-p" => parents = true,
            "-m" => {
                i += 1;
                if i < args.len() {
                    mode = u32::from_str_radix(args[i], 8).unwrap_or(0o755);
                }
            }
            arg if !arg.starts_with('-') => paths.push(arg),
            _ => {}
        }
        i += 1;
    }

    for path in paths {
        if parents {
            create_parents(path, mode)?;
        } else {
            crate::fs::mkdir(path, mode)
                .map_err(|_| alloc::format!("mkdir failed: {}", path))?;
        }
    }

    Ok(())
}

fn create_parents(path: &str, mode: u32) -> Result<(), String> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = String::new();

    for component in components {
        current.push('/');
        current.push_str(component);

        if !path_exists(&current) {
            crate::fs::mkdir(&current, mode)
                .map_err(|_| alloc::format!("mkdir failed: {}", current))?;
        }
    }

    Ok(())
}

fn cmd_rmdir(args: &[&str]) -> Result<(), String> {
    for path in args {
        if path.starts_with('-') {
            continue;
        }
        let _ = crate::fs::rmdir(path);
    }
    Ok(())
}

fn cmd_rm(args: &[&str]) -> Result<(), String> {
    let mut recursive = false;
    let mut force = false;

    for arg in args {
        match *arg {
            "-r" | "-R" | "--recursive" => recursive = true,
            "-f" | "--force" => force = true,
            "-rf" | "-fr" => {
                recursive = true;
                force = true;
            }
            path if !path.starts_with('-') => {
                if recursive {
                    let _ = remove_recursive(path);
                } else {
                    let result = crate::fs::unlink(path);
                    if result.is_err() && !force {
                        return Err(alloc::format!("rm failed: {}", path));
                    }
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn remove_recursive(path: &str) -> Result<(), String> {
    if crate::fs::is_directory(path) {
        if let Some(entries) = crate::fs::vfs::get_vfs().and_then(|v| v.list_dir(path).ok()) {
            for entry in entries {
                let full = alloc::format!("{}/{}", path, entry);
                remove_recursive(&full)?;
            }
        }
        let _ = crate::fs::rmdir(path);
    } else {
        let _ = crate::fs::unlink(path);
    }
    Ok(())
}

fn cmd_cp(args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(String::from("cp: missing arguments"));
    }

    let src = args[args.len() - 2];
    let dst = args[args.len() - 1];

    let data = crate::fs::read_file_bytes(src)
        .map_err(|_| alloc::format!("cp: cannot read {}", src))?;

    crate::fs::nonos_vfs::vfs_write_file(dst, &data)
        .map_err(|_| alloc::format!("cp: cannot write {}", dst))?;

    Ok(())
}

fn cmd_mv(args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(String::from("mv: missing arguments"));
    }

    let src = args[args.len() - 2];
    let dst = args[args.len() - 1];

    crate::fs::rename(src, dst)
        .map_err(|_| alloc::format!("mv: failed {} -> {}", src, dst))?;

    Ok(())
}

fn cmd_ln(args: &[&str]) -> Result<(), String> {
    let mut symbolic = false;
    let mut force = false;
    let mut targets = Vec::new();

    for arg in args {
        match *arg {
            "-s" | "--symbolic" => symbolic = true,
            "-f" | "--force" => force = true,
            "-sf" | "-fs" => {
                symbolic = true;
                force = true;
            }
            path if !path.starts_with('-') => targets.push(path),
            _ => {}
        }
    }

    if targets.len() < 2 {
        return Err(String::from("ln: missing arguments"));
    }

    let target = targets[0];
    let link = targets[1];

    if force {
        let _ = crate::fs::unlink(link);
    }

    if symbolic {
        crate::fs::symlink(target, link)
            .map_err(|_| alloc::format!("ln: failed {} -> {}", link, target))?;
    } else {
        crate::fs::link(target, link)
            .map_err(|_| alloc::format!("ln: failed {} -> {}", link, target))?;
    }

    Ok(())
}

fn cmd_chmod(args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(String::from("chmod: missing arguments"));
    }

    let mode = u32::from_str_radix(args[0], 8)
        .map_err(|_| String::from("chmod: invalid mode"))?;

    for path in &args[1..] {
        let _ = crate::fs::chmod(path, mode);
    }

    Ok(())
}

fn cmd_chown(args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(String::from("chown: missing arguments"));
    }

    let owner = args[0];
    let (uid, gid) = parse_owner(owner)?;

    for path in &args[1..] {
        let _ = crate::fs::chown(path, uid, gid);
    }

    Ok(())
}

fn parse_owner(s: &str) -> Result<(u32, u32), String> {
    if let Some((user, group)) = s.split_once(':') {
        let uid = user.parse().unwrap_or(0);
        let gid = group.parse().unwrap_or(0);
        Ok((uid, gid))
    } else {
        let uid = s.parse().unwrap_or(0);
        Ok((uid, uid))
    }
}

fn cmd_touch(args: &[&str]) -> Result<(), String> {
    for path in args {
        if path.starts_with('-') {
            continue;
        }

        if !path_exists(path) {
            let _ = crate::fs::nonos_vfs::vfs_write_file(path, &[]);
        }

        let now = crate::time::unix_timestamp();
        let _ = crate::fs::set_times(path, &[now, now]);
    }

    Ok(())
}

fn cmd_echo(args: &[&str]) -> Result<(), String> {
    let msg = args.join(" ");
    crate::info!("npkg: {}", msg);
    Ok(())
}

fn cmd_set(env: &mut ScriptEnv, args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Ok(());
    }

    let name = args[0];
    let value = args[1..].join(" ");
    env.variables.insert(String::from(name), value);

    Ok(())
}

fn cmd_ldconfig() -> Result<(), String> {
    crate::info!("npkg: updating library cache");
    Ok(())
}

fn cmd_update_desktop() -> Result<(), String> {
    crate::info!("npkg: updating desktop database");
    Ok(())
}

fn cmd_update_mime() -> Result<(), String> {
    crate::info!("npkg: updating MIME database");
    Ok(())
}

fn cmd_fc_cache() -> Result<(), String> {
    crate::info!("npkg: updating font cache");
    Ok(())
}

fn cmd_systemctl(args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Ok(());
    }

    let action = args[0];
    let service = args[1];

    crate::info!("npkg: {} service {}", action, service);
    Ok(())
}

fn path_exists(path: &str) -> bool {
    crate::fs::vfs::get_vfs()
        .map(|vfs| vfs.exists(path))
        .unwrap_or(false)
}
