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

pub mod firmware;
pub mod handoff;
mod init;

#[cfg(target_arch = "x86_64")]
pub mod main;

mod panic;
pub mod vga;

// Dead-at-boot trees: zero callers on the live boot path. Kept under
// the legacy gate while migration deletes them. The microkernel build
// does not compile them.
#[cfg(feature = "nonos-legacy-tree")]
pub mod early;
#[cfg(feature = "nonos-legacy-tree")]
pub mod multiboot;
#[cfg(feature = "nonos-legacy-tree")]
pub mod stage1;
#[cfg(feature = "nonos-legacy-tree")]
pub mod validation;

pub use handoff::{get_handoff, is_initialized, total_memory};
pub use handoff::{BootHandoffV1, HandoffError, HANDOFF_MAGIC, HANDOFF_VERSION};
pub use init::{
    init_early, init_panic_handler, init_vga_output, serial_print_wrapper as _serial_print,
};
pub use panic::{
    disable_interrupts, enable_interrupts, halt, halt_loop, interrupts_enabled, without_interrupts,
};
pub use vga::{clear_screen, show_boot_splash, show_panic, write_string};

#[cfg(feature = "nonos-legacy-tree")]
pub use multiboot as nonos_multiboot;
#[cfg(feature = "nonos-legacy-tree")]
pub use multiboot::{detect_platform, ConsoleType, MultibootError, MultibootInfo, Platform};
#[cfg(feature = "nonos-legacy-tree")]
pub use stage1::{
    serial_print, BootInfo, FramebufferInfo, MemoryDescriptor, EFI_CONVENTIONAL_MEMORY,
};
#[cfg(feature = "nonos-legacy-tree")]
pub use validation::{
    validate_boot_params, validate_memory_map, BootParams, BootParamsError, MemoryMapError,
};

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::boot::_serial_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => { $crate::serial_print!("{}\n", format_args!($($arg)*)) };
}
