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
        "audio" => Some(svc_audio),
        "gpu" => Some(svc_gpu),
        "apps" => Some(svc_apps),
        "agents" => Some(svc_agents),
        "shell" => Some(svc_shell),
        "desktop" => Some(svc_desktop),
        _ => None,
    }
}

fn svc_vfs() { crate::userspace::run_vfs_service(); }
fn svc_net() { crate::userspace::run_net_service(); }
fn svc_display() { crate::userspace::run_display_service(); }
fn svc_drivers() { crate::userspace::run_driver_manager(); }
fn svc_crypto() { crate::userspace::run_crypto_service(); }
fn svc_zk() { crate::userspace::run_zk_service(); }
fn svc_input() { crate::userspace::run_input_service(); }
fn svc_audio() { crate::userspace::run_audio_service(); }
fn svc_gpu() { crate::userspace::run_gpu_service(); }
fn svc_apps() { crate::userspace::run_apps_service(); }
fn svc_agents() { crate::userspace::run_agents_service(); }
fn svc_shell() { crate::userspace::run_shell_service(); }

fn svc_desktop() {
    crate::sys::serial::println(b"[DESKTOP] Service started");
    crate::graphics::framebuffer::fill_rect(0, 0, 100, 100, 0xFF00FF00);
    if crate::boot::main::graphics_init::init_graphics_for_microkernel() {
        crate::sys::serial::println(b"[DESKTOP] Running desktop loop");
        crate::boot::main::desktop_run::run_desktop();
    }
    crate::sys::serial::println(b"[DESKTOP] Failed to init graphics");
    loop { crate::sched::yield_now(); }
}
