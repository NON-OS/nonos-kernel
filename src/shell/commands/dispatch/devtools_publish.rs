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

use crate::fs::ramfs;
use crate::graphics::framebuffer::{COLOR_ACCENT, COLOR_GREEN, COLOR_RED};
use crate::sdk::manifest::{AppManifest, AppPermission};
use crate::sdk::registry::register_app;
use crate::shell::output::print_line;

pub(super) fn publish_project() {
    print_line(b"Publishing to NOX App Store...", COLOR_ACCENT);
    let manifest_data = match ramfs::read_file("/ram/dev/current/manifest.toml") {
        Ok(d) => d,
        Err(_) => {
            print_line(b"No manifest found. Run 'nox build' first", COLOR_RED);
            return;
        }
    };
    let manifest = parse_manifest(&manifest_data);
    match register_app(manifest) {
        Some(id) => {
            print_line(alloc::format!("Published! App ID: {}", id).as_bytes(), COLOR_GREEN);
            print_line(b"Your app is now live in the Marketplace", COLOR_ACCENT);
        }
        None => print_line(b"Publish failed - store full", COLOR_RED),
    }
}

fn parse_manifest(data: &[u8]) -> AppManifest {
    let mut m = AppManifest::empty();
    let s = core::str::from_utf8(data).unwrap_or("");
    for line in s.lines() {
        let line = line.trim();
        if line.starts_with("name") {
            copy_quoted(line, &mut m.name);
        } else if line.starts_with("version") {
            copy_quoted(line, &mut m.version);
        } else if line.starts_with("author") {
            copy_quoted(line, &mut m.author);
        } else if line.starts_with("price_nox") {
            m.price_nox = parse_num(line);
        } else if line.starts_with("category") {
            m.category = parse_num(line) as u8;
        } else if line.starts_with("storage") && line.contains("true") {
            m.permissions[m.perm_count as usize] = AppPermission::Storage;
            m.perm_count += 1;
        }
    }
    m
}

fn copy_quoted(line: &str, dest: &mut [u8]) {
    if let Some(q1) = line.find('"') {
        if let Some(q2) = line[q1 + 1..].find('"') {
            let val = &line[q1 + 1..q1 + 1 + q2];
            let len = val.len().min(dest.len());
            dest[..len].copy_from_slice(&val.as_bytes()[..len]);
        }
    }
}

fn parse_num(line: &str) -> u32 {
    line.split('=').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}
