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

mod types;
mod storage;
mod arch_prctl;
mod set_thread_area;
mod get_thread_area;
mod msr;
mod gdt;

pub use types::{UserDesc, TlsDescriptor, GdtEntry64, GDT_ENTRY_TLS_MIN, GDT_ENTRY_TLS_ENTRIES};
pub use types::{ARCH_SET_FS, ARCH_GET_FS, ARCH_SET_GS, ARCH_GET_GS, ARCH_GET_CPUID, ARCH_SET_CPUID};
pub use types::{MSR_FS_BASE, MSR_GS_BASE, MSR_KERNEL_GS_BASE};
pub use storage::{ThreadTlsState, get_or_create_state, clone_tls_state, clear_tls_state};
pub use storage::{set_fs_base, get_fs_base, set_gs_base, get_gs_base, set_kernel_gs_base};
pub use arch_prctl::{handle_arch_prctl, restore_tls_for_thread, save_tls_for_thread};
pub use set_thread_area::{handle_set_thread_area, set_thread_area_kernel, allocate_tls_for_thread};
pub use get_thread_area::{handle_get_thread_area, get_thread_area_kernel, get_all_tls_descriptors};
pub use msr::{read_msr, write_msr, rdfsbase, wrfsbase, rdgsbase, wrgsbase, swapgs};
pub use msr::{check_fsgsbase_support, enable_fsgsbase, is_fsgsbase_enabled};
pub use gdt::{install_tls_descriptor, clear_tls_descriptor, get_gdt_base, load_gdt};
