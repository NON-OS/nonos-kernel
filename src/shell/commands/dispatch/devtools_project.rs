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
use alloc::{format, string::ToString};

pub(super) fn create_project(name: &str) {
    let dir = format!("/ram/dev/{}", name);
    let _ = ramfs::create_dir(&dir);
    let manifest = format!("[app]\nname = \"{}\"\nversion = \"1.0.0\"\nauthor = \"Developer\"\nprice_nox = 0\ncategory = 3\n\n[permissions]\nstorage = true\n", name);
    let _ = ramfs::write_file(&format!("{}/manifest.toml", dir), manifest.as_bytes());
    let main = b"// Your app entry point\npub fn main() {\n    // App code here\n}\n";
    let _ = ramfs::write_file(&format!("{}/main.rs", dir), main);
    print_line(format!("Created project: {}", dir).as_bytes(), COLOR_GREEN);
    print_line(b"  manifest.toml - App configuration", COLOR_WHITE);
    print_line(b"  main.rs       - Entry point", COLOR_WHITE);
    print_line(b"", COLOR_WHITE);
    print_line(b"Edit manifest.toml to configure your app", COLOR_ACCENT);
    print_line(b"Run 'nox build' when ready", COLOR_ACCENT);
}

pub(super) fn set_price(amount: Option<&str>) {
    let nox = amount.and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    if let Ok(data) = ramfs::read_file("/ram/dev/current/manifest.toml") {
        let s = core::str::from_utf8(&data).unwrap_or("");
        let new = s
            .lines()
            .map(|l| {
                if l.starts_with("price_nox") {
                    format!("price_nox = {}", nox)
                } else {
                    l.to_string()
                }
            })
            .collect::<alloc::vec::Vec<_>>()
            .join("\n");
        let _ = ramfs::write_file("/ram/dev/current/manifest.toml", new.as_bytes());
        print_line(format!("Price set: {} NOX", nox).as_bytes(), COLOR_GREEN);
    } else {
        print_line(b"No project. Run 'nox init <name>' first", COLOR_RED);
    }
}

pub(super) fn show_status() {
    if let Ok(data) = ramfs::read_file("/ram/dev/current/manifest.toml") {
        print_line(b"Project Status", COLOR_ACCENT);
        print_line(b"==============", COLOR_WHITE);
        for line in core::str::from_utf8(&data).unwrap_or("").lines().take(10) {
            print_line(line.as_bytes(), COLOR_WHITE);
        }
    } else {
        print_line(b"No active project", COLOR_RED);
    }
}
