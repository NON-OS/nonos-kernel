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
mod api_getters;
mod api_init;
pub mod cache;
mod cache_assoc;
mod cache_detect;
pub mod cache_extended;
mod cache_types;
pub mod control;
mod control_fence;
mod control_intr;
pub mod cpuid;
mod cpuid_core;
mod cpuid_leaf;
pub mod cpuid_stats;
pub mod error;
pub mod features;
pub mod frequency;
mod frequency_api;
pub mod frequency_cpuid;
pub mod frequency_pit;
pub mod identification;
mod identification_detect;
mod identification_types;
pub mod msr;
mod msr_core;
mod msr_safe;
pub mod msr_stats;
pub mod per_cpu;
pub mod state;
mod state_getters;
pub mod state_globals;
mod state_init;
mod state_stats;
pub mod thermal;
pub mod topology;
mod topology_detect;
pub mod topology_leaf0b;
mod topology_types;
pub mod tsc;
mod vendor;

pub use api::{
    cache_info, cpu_count, cpu_id, current_cpu_id, features, get_stats, has_feature, init, init_ap,
    is_initialized, per_cpu_data, topology, vendor,
};
pub use cache::{CacheInfo, CacheLevel, CacheType};
pub use cache_extended::detect_extended;
pub use control::{cli, hlt, interrupts_enabled, lfence, mfence, pause, serialize, sfence, sti};
pub use cpuid::{cpuid, cpuid_count, cpuid_max_extended_leaf, cpuid_max_leaf};
pub use cpuid_stats::increment_calls;
pub use error::CpuError;
pub use features::CpuFeatures;
pub use frequency::{core_frequency, tsc_frequency};
pub use frequency_cpuid::{detect_frequency_cpuid_16h, detect_tsc_frequency_cpuid_15h};
pub use frequency_pit::calibrate_tsc_with_pit;
pub use identification::CpuId;
pub use msr::{rdmsr, try_rdmsr, try_wrmsr, wrmsr};
pub use msr_stats::{increment_reads, increment_writes};
pub use per_cpu::{PerCpuData, MAX_CPUS};
pub use state::CpuStats;
pub use state_globals::{
    AP_DATA, BSP_DATA, CACHE_INFO, CPU_COUNT, CPU_FEATURES, CPU_ID, INITIALIZED, TOPOLOGY,
};
pub use thermal::{current_pstate, set_power_state, temperature, tj_max, PowerState};
pub use topology::CpuTopology;
pub use topology_leaf0b::detect_leaf_0b;
pub use tsc::{rdtsc, rdtsc_serialized, rdtscp};
pub use vendor::CpuVendor;
