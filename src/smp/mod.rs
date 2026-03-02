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

mod constants;
mod types;
mod state;
mod cpu;
mod preempt;
mod tlb;
mod ipi_handler;
mod stats;
mod init;
mod ap;

pub mod percpu;
pub mod topology;
pub mod ipi;

pub use constants::*;
pub use types::{CpuState, CpuDescriptor, SmpStats, CpuStats};
pub(crate) use state::{cpu_count, cpus_online};
pub use cpu::{cpu_id, apic_to_cpu_id, current_cpu, get_cpu, is_bsp};
pub use preempt::{preempt_disable, preempt_enable, preempt_enabled};
pub use tlb::{tlb_shootdown, handle_tlb_shootdown_ipi, flush_tlb};
pub use ipi_handler::{send_reschedule_ipi, send_panic_ipi, handle_panic_ipi, handle_stop_ipi};
pub use stats::get_smp_stats;
pub use init::{init_bsp, start_aps};
pub use ap::ap_entry;
