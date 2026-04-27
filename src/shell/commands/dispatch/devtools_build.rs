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
use crate::graphics::framebuffer::{COLOR_ACCENT, COLOR_GREEN, COLOR_RED, COLOR_WHITE};
use crate::shell::output::print_line;
use alloc::vec::Vec;

pub(super) fn build_project() {
    print_line(b"Building app package...", COLOR_ACCENT);
    let manifest = match ramfs::read_file("/ram/dev/current/manifest.toml") {
        Ok(d) => d,
        Err(_) => {
            print_line(b"No manifest.toml found", COLOR_RED);
            return;
        }
    };
    let main = match ramfs::read_file("/ram/dev/current/main.rs") {
        Ok(d) => d,
        Err(_) => {
            print_line(b"No main.rs found", COLOR_RED);
            return;
        }
    };
    let mut package = Vec::new();
    package.extend_from_slice(b"NOXAPP01");
    package.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    package.extend_from_slice(&manifest);
    package.extend_from_slice(&(main.len() as u32).to_le_bytes());
    package.extend_from_slice(&main);
    let hash = simple_hash(&package);
    package.extend_from_slice(&hash);
    let name = extract_name(&manifest);
    let path = alloc::format!("/ram/dev/{}.noxapp", name);
    match ramfs::write_file(&path, &package) {
        Ok(_) => {
            print_line(alloc::format!("Built: {}", path).as_bytes(), COLOR_GREEN);
            print_line(alloc::format!("Size: {} bytes", package.len()).as_bytes(), COLOR_WHITE);
            print_line(b"Run 'nox publish' to submit", COLOR_ACCENT);
        }
        Err(_) => print_line(b"Build failed", COLOR_RED),
    }
}

fn extract_name(manifest: &[u8]) -> &str {
    let s = core::str::from_utf8(manifest).unwrap_or("");
    for line in s.lines() {
        if line.starts_with("name") {
            if let Some(q1) = line.find('"') {
                if let Some(q2) = line[q1 + 1..].find('"') {
                    return &line[q1 + 1..q1 + 1 + q2];
                }
            }
        }
    }
    "app"
}

fn simple_hash(data: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, &b) in data.iter().enumerate() {
        h[i % 32] ^= b.wrapping_add(i as u8);
    }
    h
}
