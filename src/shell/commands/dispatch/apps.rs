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

use crate::shell::commands::apps::*;
use crate::shell::commands::misc::*;
use crate::shell::commands::modules::*;
use crate::shell::commands::utils::starts_with;

pub fn try_dispatch_apps(cmd: &[u8]) -> bool {
    if cmd == b"lsmod" {
        cmd_lsmod();
    } else if cmd == b"modinfo" || starts_with(cmd, b"modinfo ") {
        cmd_modinfo(cmd);
    } else if cmd == b"insmod" || starts_with(cmd, b"insmod ") {
        cmd_insmod(cmd);
    } else if cmd == b"rmmod" || starts_with(cmd, b"rmmod ") {
        cmd_rmmod(cmd);
    } else if cmd == b"depmod" {
        cmd_depmod();
    } else if cmd == b"sysctl" || starts_with(cmd, b"sysctl ") {
        cmd_sysctl(cmd);
    } else if cmd == b"kver" || cmd == b"kernel" {
        cmd_kver();
    } else if cmd == b"capsule" || cmd == b"capsules" {
        cmd_capsules();
    } else if cmd == b"neofetch" || cmd == b"screenfetch" {
        cmd_neofetch();
    } else if cmd == b"logo" {
        cmd_logo();
    } else if cmd == b"apps" || cmd == b"applications" {
        cmd_apps();
    } else if cmd == b"firefox" || cmd == b"browser" {
        cmd_open_browser();
    } else if cmd == b"files" || cmd == b"filemanager" {
        cmd_open_files();
    } else if cmd == b"editor" || cmd == b"edit" || cmd == b"notepad" {
        cmd_open_editor();
    } else if cmd == b"calc" || cmd == b"calculator" {
        cmd_open_calculator();
    } else if cmd == b"settings" {
        cmd_open_settings();
    } else if cmd == b"sysmon" {
        cmd_open_monitor();
    } else {
        return false;
    }
    true
}
