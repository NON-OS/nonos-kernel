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

use super::{
    run_agents_service, run_apps_service, run_audio_service, run_crypto_service,
    run_display_service, run_driver_manager, run_gpu_service, run_input_service, run_net_service,
    run_shell_service, run_vfs_service, run_zk_service,
};

pub fn run_service_by_name(name: &str) -> ! {
    match name {
        "vfs" => run_vfs_service(),
        "network" => run_net_service(),
        "display" => run_display_service(),
        "drivers" => run_driver_manager(),
        "crypto" => run_crypto_service(),
        "zk" => run_zk_service(),
        "input" => run_input_service(),
        "audio" => run_audio_service(),
        "gpu" => run_gpu_service(),
        "apps" => run_apps_service(),
        "agents" => run_agents_service(),
        "shell" => run_shell_service(),
        "desktop" => run_desktop_service(),
        _ => loop {
            crate::sched::yield_now();
        },
    }
}

fn run_desktop_service() -> ! {
    crate::sys::serial::println(b"[DESKTOP] Service started");
    #[cfg(target_arch = "x86_64")]
    {
        if crate::boot::main::graphics_init::init_graphics_for_microkernel() {
            crate::sys::serial::println(b"[DESKTOP] Running desktop loop");
            crate::boot::main::desktop_run::run_desktop();
        }
    }
    crate::sys::serial::println(b"[DESKTOP] Failed to init graphics");
    loop {
        crate::sched::yield_now();
    }
}
