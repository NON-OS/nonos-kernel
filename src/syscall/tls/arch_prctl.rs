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

use super::msr::{read_msr, write_msr};
use super::storage::*;
use super::types::*;
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::write_user_value;

pub fn handle_arch_prctl(code: i32, addr: u64) -> SyscallResult {
    let tid = crate::process::current_tid() as u64;
    match code {
        ARCH_SET_FS => do_set_fs(tid, addr),
        ARCH_GET_FS => do_get_fs(tid, addr),
        ARCH_SET_GS => do_set_gs(tid, addr),
        ARCH_GET_GS => do_get_gs(tid, addr),
        ARCH_GET_CPUID => do_get_cpuid(tid, addr),
        ARCH_SET_CPUID => do_set_cpuid(tid, addr),
        ARCH_MAP_VDSO_X32 | ARCH_MAP_VDSO_32 | ARCH_MAP_VDSO_64 => errno(22),
        _ => errno(22),
    }
}

fn do_set_fs(tid: u64, base: u64) -> SyscallResult {
    if !is_canonical_address(base) {
        return errno(22);
    }
    set_fs_base(tid, base);
    write_msr(MSR_FS_BASE, base);
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn do_get_fs(tid: u64, addr: u64) -> SyscallResult {
    let base = get_fs_base(tid);
    if write_user_value(addr, &base).is_err() {
        return errno(14);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn do_set_gs(tid: u64, base: u64) -> SyscallResult {
    if !is_canonical_address(base) {
        return errno(22);
    }
    set_gs_base(tid, base);
    write_msr(MSR_GS_BASE, base);
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn do_get_gs(tid: u64, addr: u64) -> SyscallResult {
    let base = get_gs_base(tid);
    if write_user_value(addr, &base).is_err() {
        return errno(14);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn do_get_cpuid(tid: u64, addr: u64) -> SyscallResult {
    let enabled = if get_cpuid_enabled(tid) { 1u64 } else { 0u64 };
    if write_user_value(addr, &enabled).is_err() {
        return errno(14);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn do_set_cpuid(tid: u64, val: u64) -> SyscallResult {
    if val > 1 {
        return errno(22);
    }
    set_cpuid_enabled(tid, val == 1);
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

fn is_canonical_address(addr: u64) -> bool {
    let sign_ext = (addr as i64) >> 47;
    sign_ext == 0 || sign_ext == -1
}

pub fn restore_tls_for_thread(tid: u64) {
    let state = get_or_create_state(tid);
    write_msr(MSR_FS_BASE, state.fs_base);
    write_msr(MSR_GS_BASE, state.gs_base);
    write_msr(MSR_KERNEL_GS_BASE, state.kernel_gs_base);
}

pub fn save_tls_for_thread(tid: u64) {
    set_fs_base(tid, read_msr(MSR_FS_BASE));
    set_gs_base(tid, read_msr(MSR_GS_BASE));
    set_kernel_gs_base(tid, read_msr(MSR_KERNEL_GS_BASE));
}
