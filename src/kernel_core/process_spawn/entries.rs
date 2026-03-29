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

pub(crate) fn get_service_entry(name: &str) -> Option<fn()> {
    match name {
        "vfs" => Some(svc_vfs),
        "network" => Some(svc_net),
        "display" => Some(svc_display),
        "drivers" => Some(svc_drivers),
        "crypto" => Some(svc_crypto),
        "zk" => Some(svc_zk),
        "input" => Some(svc_input),
        _ => None,
    }
}

fn svc_vfs() {
    crate::sys::serial::println(b"[SVC] VFS entry!");
    crate::userspace::run_vfs_service();
}

fn svc_net() {
    crate::sys::serial::println(b"[SVC] NET entry!");
    crate::userspace::run_net_service();
}

fn svc_display() {
    crate::sys::serial::println(b"[SVC] DISP entry!");
    crate::userspace::run_display_service();
}

fn svc_drivers() {
    crate::sys::serial::println(b"[SVC] DRV entry!");
    crate::userspace::run_driver_manager();
}

fn svc_crypto() {
    crate::sys::serial::println(b"[SVC] CRYPTO entry!");
    crate::userspace::run_crypto_service();
}

fn svc_zk() {
    crate::sys::serial::println(b"[SVC] ZK entry!");
    crate::userspace::run_zk_service();
}

fn svc_input() {
    crate::sys::serial::println(b"[SVC] INPUT entry!");
    crate::userspace::run_input_service();
}
