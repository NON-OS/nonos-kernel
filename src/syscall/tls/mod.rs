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

mod arch_prctl;
mod gdt;
mod get_thread_area;
mod msr;
mod set_thread_area;
mod storage;
mod types;

pub use arch_prctl::{handle_arch_prctl, restore_tls_for_thread, save_tls_for_thread};
pub use gdt::*;
pub use get_thread_area::*;
pub use msr::{check_fsgsbase_support, enable_fsgsbase, is_fsgsbase_enabled};
pub use msr::{rdfsbase, rdgsbase, read_msr, swapgs, wrfsbase, wrgsbase, write_msr};
pub use set_thread_area::*;
pub use storage::*;
pub use types::*;
