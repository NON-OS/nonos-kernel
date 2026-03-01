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

use core::sync::atomic::Ordering;

use crate::syscall::SyscallResult;
use crate::syscall::dispatch::errno;

pub fn handle_admin_reboot() -> SyscallResult {
    let Some(proc) = crate::process::current_process() else {
        return errno(1);
    };

    if !proc.capability_token().grants(crate::capabilities::Capability::Admin) {
        return errno(1);
    }

    crate::log::info!("ADMIN: System reboot requested by pid {}", proc.pid);

    crate::security::secure_wipe_all_memory();

    unsafe {
        core::arch::asm!(
            "cli",
            "out 0x64, al",
            in("al") 0xFEu8,
            options(nostack, nomem)
        );
    }

    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

pub fn handle_admin_shutdown() -> SyscallResult {
    let Some(proc) = crate::process::current_process() else {
        return errno(1);
    };

    if !proc.capability_token().grants(crate::capabilities::Capability::Admin) {
        return errno(1);
    }

    crate::log::info!("ADMIN: System shutdown requested by pid {}", proc.pid);

    crate::security::secure_wipe_all_memory();

    unsafe {
        core::arch::asm!(
            "cli",
            "out dx, ax",
            in("dx") 0x604u16,
            in("ax") 0x2000u16,
            options(nostack, nomem)
        );

        core::arch::asm!("hlt");
    }

    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

pub fn handle_admin_mod_load(name_ptr: u64, name_len: u64, code_ptr: u64, code_len: u64, sig_ptr: u64) -> SyscallResult {
    let Some(proc) = crate::process::current_process() else {
        return errno(1);
    };

    if !proc.capability_token().grants(crate::capabilities::Capability::Admin) {
        return errno(1);
    }

    if name_ptr == 0 || code_ptr == 0 || sig_ptr == 0 {
        return errno(22);
    }
    if name_len == 0 || name_len > 256 || code_len == 0 || code_len > 16 * 1024 * 1024 {
        return errno(22);
    }

    let name_slice = unsafe {
        core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize)
    };
    let name = match core::str::from_utf8(name_slice) {
        Ok(s) => s,
        Err(_) => return errno(22),
    };

    let code = unsafe {
        core::slice::from_raw_parts(code_ptr as *const u8, code_len as usize)
    };

    let sig = unsafe {
        let ptr = sig_ptr as *const [u8; 64];
        &*ptr
    };

    use crate::modules::nonos_module_loader::{NONOS_MODULE_LOADER, NonosModuleType};

    match NONOS_MODULE_LOADER.load_module(
        name,
        NonosModuleType::Application,
        code.to_vec(),
        sig
    ) {
        Ok(module_id) => {
            crate::log_info!("ADMIN: Module '{}' loaded with id {} by pid {}", name, module_id, proc.pid);
            SyscallResult { value: module_id as i64, capability_consumed: false, audit_required: true }
        }
        Err(e) => {
            crate::log_warn!("ADMIN: Module load failed: {}", e);
            errno(22)
        }
    }
}

pub fn handle_admin_cap_grant(target_pid: u32, caps_bits: u64, _ttl_ms: u64) -> SyscallResult {
    let Some(proc) = crate::process::current_process() else {
        return errno(1);
    };

    if !proc.capability_token().grants(crate::capabilities::Capability::Admin) {
        return errno(1);
    }

    use crate::process::nonos_core::PROCESS_TABLE;
    let Some(pcb) = PROCESS_TABLE.find_by_pid(target_pid) else {
        return errno(3);
    };

    if caps_bits == 0 {
        return errno(22);
    }

    let old_caps = pcb.caps_bits.load(Ordering::SeqCst);
    let new_caps = old_caps | caps_bits;
    pcb.caps_bits.store(new_caps, Ordering::SeqCst);

    crate::log_info!("ADMIN: Granted caps 0x{:x} to pid {} by pid {} (now 0x{:x})",
                     caps_bits, target_pid, proc.pid, new_caps);
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_admin_cap_revoke(target_pid: u32, caps_bits: u64) -> SyscallResult {
    let Some(proc) = crate::process::current_process() else {
        return errno(1);
    };

    if !proc.capability_token().grants(crate::capabilities::Capability::Admin) {
        return errno(1);
    }

    use crate::process::nonos_core::PROCESS_TABLE;
    let Some(pcb) = PROCESS_TABLE.find_by_pid(target_pid) else {
        return errno(3);
    };

    let old_caps = pcb.caps_bits.load(Ordering::SeqCst);

    if caps_bits == 0 {
        pcb.caps_bits.store(0, Ordering::SeqCst);
        crate::log_info!("ADMIN: Revoked ALL caps from pid {} by pid {} (was 0x{:x})",
                         target_pid, proc.pid, old_caps);
    } else {
        let new_caps = old_caps & !caps_bits;
        pcb.caps_bits.store(new_caps, Ordering::SeqCst);
        crate::log_info!("ADMIN: Revoked caps 0x{:x} from pid {} by pid {} (now 0x{:x})",
                         caps_bits, target_pid, proc.pid, new_caps);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
