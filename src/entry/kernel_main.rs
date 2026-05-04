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

use super::vga_error::halt_loop;
#[cfg(feature = "nonos-legacy-tree")]
use super::vga_error::early_vga_error;

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    crate::boot::init_vga_output();
    crate::boot::init_panic_handler();
    crate::boot::init_early();

    init_smp_bsp();

    // Legacy bring-up: the broad driver stack, the legacy security
    // monitor, the in-kernel filesystem, the desktop framebuffer, and
    // the optional zksync/runtime/npkg paths. None of these are part
    // of the microkernel trusted path; the boot path here is
    // pci/virtio_rng (already done in `init_core_systems`), then
    // straight to the scheduler.
    #[cfg(feature = "nonos-legacy-tree")]
    {
        if let Err(err) = crate::drivers::init_all_drivers() {
            early_vga_error(format_args!("DRIVERS INIT FAILED: {:#?}", err));
            halt_loop();
        }

        if let Err(err) = crate::security::init_all_security() {
            early_vga_error(format_args!("SECURITY INIT FAILED: {}", err));
            halt_loop();
        }

        init_filesystem();
        crate::elf::loader::init_elf_loader();
        init_graphics();

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
    }

    #[cfg(not(feature = "nonos-legacy-tree"))]
    {
        // Microkernel boot bring-up: the only thing the trusted path
        // adds at this layer is the canonical ELF loader. Everything
        // else (memory map, IPC, scheduler, capability gate, kernel
        // keys, network stack-if-any) is handled by `microkernel_init`
        // via `boot_microkernel`.
        crate::elf::loader::init_elf_loader();
    }

    init_smp_aps();

    #[cfg(feature = "nonos-legacy-tree")]
    crate::drivers::console::write_message("kernel online");

    #[cfg(feature = "sched")]
    {
        crate::sched::enter();
    }

    #[cfg(not(feature = "sched"))]
    halt_loop();
}

fn init_smp_bsp() {
    #[cfg(target_arch = "x86_64")]
    {
        if let Err(e) = crate::smp::init_bsp() {
            crate::log_warn!("SMP BSP init: {}", e);
        }
    }
}

fn init_smp_aps() {
    #[cfg(target_arch = "x86_64")]
    {
        match crate::smp::start_aps() {
            Ok(count) => {
                if count > 0 {
                    #[cfg(feature = "nonos-legacy-tree")]
                    crate::drivers::console::write_message(&alloc::format!(
                        "SMP: {} application processors online",
                        count
                    ));
                    #[cfg(not(feature = "nonos-legacy-tree"))]
                    crate::sys::serial::print_dec(count as u64);
                }
            }
            Err(e) => crate::log_warn!("SMP AP startup: {}", e),
        }
    }
}

#[cfg(feature = "nonos-legacy-tree")]
fn init_filesystem() {
    crate::fs::init();
    crate::drivers::console::write_message("Filesystem: VFS + devfs + procfs + sysfs mounted");
}

#[cfg(feature = "nonos-legacy-tree")]
fn init_graphics() {
    if let Err(_) = crate::graphics::init_graphics_subsystem() {
        crate::log_info!("Graphics: framebuffer mode");
    } else {
        crate::drivers::console::write_message("Graphics: DRM/KMS initialized");
    }
}
