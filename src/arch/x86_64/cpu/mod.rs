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

mod api;
mod api_init;
mod api_getters;
pub mod cache;
mod cache_types;
mod cache_detect;
mod cache_extended;
mod cache_assoc;
pub mod control;
mod control_fence;
mod control_intr;
pub mod cpuid;
mod cpuid_core;
mod cpuid_stats;
mod cpuid_leaf;
pub mod error;
pub mod features;
pub mod frequency;
mod frequency_cpuid;
mod frequency_pit;
mod frequency_api;
pub mod identification;
mod identification_types;
mod identification_detect;
pub mod msr;
mod msr_core;
mod msr_stats;
mod msr_safe;
pub mod per_cpu;
pub mod state;
mod state_globals;
mod state_init;
mod state_getters;
mod state_stats;
pub mod thermal;
pub mod topology;
mod topology_types;
mod topology_detect;
mod topology_leaf0b;
pub mod tsc;
mod vendor;

pub use api::{
    cache_info, cpu_count, cpu_id, current_cpu_id, features, get_stats, has_feature, init, init_ap,
    is_initialized, per_cpu_data, topology, vendor,
};
pub use cache::{CacheInfo, CacheLevel, CacheType};
pub use control::{cli, hlt, interrupts_enabled, lfence, mfence, pause, serialize, sfence, sti};
pub use cpuid::{cpuid, cpuid_count, cpuid_max_extended_leaf, cpuid_max_leaf};
pub use error::CpuError;
pub use features::CpuFeatures;
pub use frequency::{core_frequency, tsc_frequency};
pub use identification::CpuId;
pub use msr::{rdmsr, try_rdmsr, try_wrmsr, wrmsr};
pub use per_cpu::{PerCpuData, MAX_CPUS};
pub use state::CpuStats;
pub use thermal::{current_pstate, set_power_state, temperature, tj_max, PowerState};
pub use topology::CpuTopology;
pub use tsc::{rdtsc, rdtsc_serialized, rdtscp};
pub use vendor::CpuVendor;
