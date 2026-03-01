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

pub mod spectre_mitigations;
pub mod memory_sanitization;

pub use spectre_mitigations::{
    init as spectre_init, CpuVulnerabilities, MitigationStatus, lfence, mfence, sfence,
    array_index_mask_nospec, array_access_nospec, rsb_fill, rsb_clear, ibpb, ibrs_enable,
    ibrs_disable, stibp_enable, stibp_disable, ssbd_enable, ssbd_disable, mds_clear, l1d_flush,
    kernel_entry_mitigations, kernel_exit_mitigations, context_switch_mitigations,
    detect_vulnerabilities, enable_mitigations, get_vulnerabilities, get_mitigation_status,
    are_mitigations_enabled, __x86_indirect_thunk_rax, __x86_indirect_thunk_rbx,
    __x86_indirect_thunk_rcx, __x86_indirect_thunk_rdx, __x86_indirect_thunk_rsi,
    __x86_indirect_thunk_rdi, __x86_indirect_thunk_r8,
};

pub use memory_sanitization::{
    init as memory_sanitization_init, SanitizationLevel, StackCanaryConfig, secure_zero,
    secure_zero_slice, dod_5220_erase, paranoid_erase, gutmann_erase, sanitize, sanitize_slice,
    init_stack_canary, get_stack_canary, verify_stack_canary, stack_canary_failed,
    GuardPage, allocate_with_guards, free_with_guards, SensitiveData, SecureString,
    on_free, on_realloc, sanitize_process_memory, zerostate_shutdown_wipe,
    SanitizationStats, get_stats as sanitization_stats, set_level, get_level,
};
