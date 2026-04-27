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

extern crate alloc;
use super::manager::{RepositoryManager, REPO_MANAGER};
use super::repo::Repository;
use super::types::{RepositoryConfig, RepositoryKind};
use crate::npkg::error::{NpkgError, NpkgResult};
use alloc::{format, string::String, vec::Vec};

pub(super) fn load_custom_repositories(manager: &mut RepositoryManager) -> NpkgResult<()> {
    let content_bytes = match crate::fs::read_file("/etc/npkg/repositories.conf") {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let content = core::str::from_utf8(&content_bytes).unwrap_or("");
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(config) = parse_repo_line(line) {
            if !manager.repositories.iter().any(|r| r.config.name == config.name) {
                manager.repositories.push(Repository::new(config));
            }
        }
    }
    Ok(())
}

fn parse_repo_line(line: &str) -> Option<RepositoryConfig> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let (name, url) = (String::from(parts[0]), String::from(parts[1]));
    let (mut kind, mut enabled, mut sig_required, mut priority) =
        (RepositoryKind::ThirdParty, true, true, 25u32);
    for part in parts.iter().skip(2) {
        match *part {
            "disabled" => enabled = false,
            "nosig" => sig_required = false,
            "official" => {
                kind = RepositoryKind::Official;
                priority = 100;
            }
            "community" => {
                kind = RepositoryKind::Community;
                priority = 50;
            }
            _ => {
                if let Some(p) = part.strip_prefix("priority=") {
                    if let Ok(v) = p.parse() {
                        priority = v;
                    }
                }
            }
        }
    }
    Some(RepositoryConfig { name, url, kind, enabled, signature_required: sig_required, priority })
}

pub(super) fn save_repositories() -> NpkgResult<()> {
    let guard = REPO_MANAGER.read();
    let manager =
        guard.as_ref().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
    let mut content = String::from("# NONOS Package Manager Repository Configuration\n\n");
    for repo in &manager.repositories {
        let cfg = &repo.config;
        if cfg.kind == RepositoryKind::Official || cfg.kind == RepositoryKind::Community {
            continue;
        }
        content.push_str(&cfg.name);
        content.push(' ');
        content.push_str(&cfg.url);
        if !cfg.enabled {
            content.push_str(" disabled");
        }
        if !cfg.signature_required {
            content.push_str(" nosig");
        }
        content.push_str(&format!(" priority={}\n", cfg.priority));
    }
    let _ = crate::fs::mkdir("/etc/npkg", 0o755);
    crate::fs::nonos_vfs::vfs_write_file("/etc/npkg/repositories.conf", content.as_bytes())
        .map_err(|_| NpkgError::IoError(String::from("failed to save config")))?;
    Ok(())
}
