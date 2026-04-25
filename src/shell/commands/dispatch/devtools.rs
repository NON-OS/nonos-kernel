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

use crate::graphics::framebuffer::{COLOR_ACCENT, COLOR_WHITE};
use crate::shell::output::print_line;

pub fn try_dispatch_dev(cmd: &[u8]) -> bool {
    let s = core::str::from_utf8(cmd).unwrap_or("");
    if !s.starts_with("dev ") && s != "dev" {
        return false;
    }
    let parts: alloc::vec::Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 2 {
        dev_help();
        return true;
    }
    match parts[1] {
        "init" => dev_init(parts.get(2).copied()),
        "build" => dev_build(),
        "price" => dev_price(parts.get(2).copied()),
        "publish" => dev_publish(),
        "status" => dev_status(),
        "help" | _ => dev_help(),
    }
    true
}

fn dev_help() {
    print_line(b"NOX Developer Tools", COLOR_ACCENT);
    print_line(b"===================", COLOR_WHITE);
    print_line(b"dev init <name>    Create new app project", COLOR_WHITE);
    print_line(b"dev build          Build app package (.noxapp)", COLOR_WHITE);
    print_line(b"dev price <nox>    Set price (0 = free)", COLOR_WHITE);
    print_line(b"dev publish        Submit to NOX App Store", COLOR_WHITE);
    print_line(b"dev status         Show project status", COLOR_WHITE);
}

fn dev_init(name: Option<&str>) {
    let name = name.unwrap_or("myapp");
    super::devtools_project::create_project(name);
}

fn dev_build() {
    super::devtools_build::build_project();
}
fn dev_price(amount: Option<&str>) {
    super::devtools_project::set_price(amount);
}
fn dev_publish() {
    super::devtools_publish::publish_project();
}
fn dev_status() {
    super::devtools_project::show_status();
}
