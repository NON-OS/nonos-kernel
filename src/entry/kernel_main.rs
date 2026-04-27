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

extern crate alloc;

use super::vga_error::{early_vga_error, halt_loop};

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    crate::boot::init_vga_output();
    crate::boot::init_panic_handler();
    crate::boot::init_early();

    if let Err(err) = crate::drivers::init_all_drivers() {
        early_vga_error(format_args!("DRIVERS INIT FAILED: {:#?}", err));
        halt_loop();
    }

    if let Err(err) = crate::security::init_all_security() {
        early_vga_error(format_args!("SECURITY INIT FAILED: {}", err));
        halt_loop();
    }

    if let Err(_) = crate::zksync::init_zksync(crate::zksync::config::ZkSyncConfig::default()) {
        crate::drivers::console::write_message("zksync: init skipped");
    }

    let kernel_token = crate::syscall::caps::CapabilityToken::system();
    if let Err(err) = crate::runtime::nonos_zerostate::init_runtime(&kernel_token) {
        crate::drivers::console::write_message(&alloc::format!("zerostate: {}", err));
    }

    if let Err(_) = crate::npkg::init() {
        crate::drivers::console::write_message("npkg: init deferred");
    }

    crate::drivers::console::write_message("kernel online");

    // Selftest disabled for production boot

    #[cfg(feature = "cli")]
    {
        crate::ui::cli::spawn();
    }

    #[cfg(feature = "sched")]
    {
        crate::sched::enter();
    }

    #[cfg(not(feature = "sched"))]
    halt_loop();
}
