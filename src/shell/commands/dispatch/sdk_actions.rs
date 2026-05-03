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

use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_RED, COLOR_WHITE};
use crate::sdk::{list_apps, registry};
use crate::shell::output::print_line;

pub fn list_installed() {
    let apps = list_apps();
    if apps.is_empty() {
        print_line(b"No apps installed", COLOR_WHITE);
        return;
    }
    for app in apps {
        let nlen = app.manifest.name.iter().position(|&c| c == 0).unwrap_or(64);
        let mut buf = [0u8; 80];
        let n = fmt_app_line(app.id, &app.manifest.name[..nlen], &mut buf);
        print_line(&buf[..n], COLOR_WHITE);
    }
}

fn fmt_app_line(id: u32, name: &[u8], buf: &mut [u8; 80]) -> usize {
    let mut i = fmt_u32(id, buf);
    buf[i] = b' ';
    i += 1;
    buf[i..i + name.len()].copy_from_slice(name);
    i + name.len()
}

fn fmt_u32(mut n: u32, buf: &mut [u8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let (mut i, mut tmp) = (0, [0u8; 10]);
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

pub fn app_info(id_str: &str) {
    let id: u32 = id_str.parse().unwrap_or(0);
    if let Some(app) = registry::get_app(id) {
        let nlen = app.manifest.name.iter().position(|&c| c == 0).unwrap_or(64);
        print_line(b"Name:", COLOR_WHITE);
        print_line(&app.manifest.name[..nlen], COLOR_WHITE);
        let mut buf = [0u8; 32];
        let n = fmt_u32(app.manifest.price_nox, &mut buf);
        print_line(b"Price NOX:", COLOR_WHITE);
        print_line(&buf[..n], COLOR_WHITE);
    } else {
        print_line(b"App not found", COLOR_RED);
    }
}

pub fn install_pkg(path: &str) {
    let Ok(data) = crate::fs::ramfs::read_file(path) else {
        print_line(b"Failed to read package", COLOR_RED);
        return;
    };
    let Some(pkg) = crate::sdk::unpack_app(&data) else {
        print_line(b"Invalid package format", COLOR_RED);
        return;
    };
    let Some(id) = registry::register_app(pkg.manifest) else {
        print_line(b"Failed to register app", COLOR_RED);
        return;
    };
    let mut buf = [0u8; 32];
    let n = fmt_u32(id, &mut buf);
    print_line(b"Installed app", COLOR_GREEN);
    print_line(&buf[..n], COLOR_WHITE);
}

pub fn uninstall_app(id_str: &str) {
    let id: u32 = id_str.parse().unwrap_or(0);
    if registry::uninstall_app(id) {
        print_line(b"App uninstalled", COLOR_GREEN);
    } else {
        print_line(b"App not found", COLOR_RED);
    }
}

pub fn run_app(id_str: &str) {
    let id: u32 = id_str.parse().unwrap_or(0);
    if crate::sdk::run_app(id) {
        print_line(b"App started", COLOR_GREEN);
    } else {
        print_line(b"Failed to start app", COLOR_RED);
    }
}
