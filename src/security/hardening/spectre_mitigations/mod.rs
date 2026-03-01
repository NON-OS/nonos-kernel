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
mod constants;
mod cpuid;
mod msr;
mod barriers;
mod retpoline;
mod rsb;
mod ibpb;
mod ibrs;
mod stibp;
mod ssbd;
mod mds;
mod l1d;
mod hooks;
mod detect;
mod state;
mod init;

pub use types::{CpuVulnerabilities, MitigationStatus};
pub use barriers::{lfence, mfence, sfence, array_index_mask_nospec, array_access_nospec};
pub use rsb::{rsb_fill, rsb_clear};
pub use ibpb::ibpb;
pub use ibrs::{ibrs_enable, ibrs_disable};
pub use stibp::{stibp_enable, stibp_disable};
pub use ssbd::{ssbd_enable, ssbd_disable};
pub use mds::mds_clear;
pub use l1d::l1d_flush;
pub use hooks::{kernel_entry_mitigations, kernel_exit_mitigations, context_switch_mitigations};
pub use detect::{detect_vulnerabilities, enable_mitigations};
pub use init::{init, get_vulnerabilities, get_mitigation_status, are_mitigations_enabled};
pub use retpoline::{
    __x86_indirect_thunk_rax, __x86_indirect_thunk_rbx, __x86_indirect_thunk_rcx,
    __x86_indirect_thunk_rdx, __x86_indirect_thunk_rsi, __x86_indirect_thunk_rdi,
    __x86_indirect_thunk_r8,
};
