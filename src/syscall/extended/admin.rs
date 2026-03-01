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

use crate::syscall::SyscallResult;
use super::errno;

pub fn handle_reboot(magic1: i32, magic2: i32, cmd: u32, _arg: u64) -> SyscallResult {
    const LINUX_REBOOT_MAGIC1: i32 = 0xfee1dead_u32 as i32;
    const LINUX_REBOOT_MAGIC2: i32 = 672274793;
    const LINUX_REBOOT_MAGIC2A: i32 = 85072278;
    const LINUX_REBOOT_MAGIC2B: i32 = 369367448;
    const LINUX_REBOOT_MAGIC2C: i32 = 537993216;

    const LINUX_REBOOT_CMD_RESTART: u32 = 0x01234567;
    const LINUX_REBOOT_CMD_HALT: u32 = 0xCDEF0123;
    const LINUX_REBOOT_CMD_POWER_OFF: u32 = 0x4321FEDC;

    if magic1 != LINUX_REBOOT_MAGIC1 {
        return errno(22);
    }

    if magic2 != LINUX_REBOOT_MAGIC2 && magic2 != LINUX_REBOOT_MAGIC2A
        && magic2 != LINUX_REBOOT_MAGIC2B && magic2 != LINUX_REBOOT_MAGIC2C {
        return errno(22);
    }

    match cmd {
        LINUX_REBOOT_CMD_RESTART => {
            let _ = crate::arch::x86_64::acpi::power::reboot();
        }
        LINUX_REBOOT_CMD_HALT | LINUX_REBOOT_CMD_POWER_OFF => {
            let _ = crate::arch::x86_64::acpi::power::shutdown();
        }
        _ => return errno(22),
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_init_module(module_image: u64, len: u64, param_values: u64) -> SyscallResult {
    if module_image == 0 || len == 0 {
        return errno(22);
    }

    let image = unsafe { core::slice::from_raw_parts(module_image as *const u8, len as usize) };
    let params = if param_values != 0 {
        match crate::syscall::dispatch::util::parse_string_from_user(param_values, 4096) {
            Ok(s) => Some(s),
            Err(_) => return errno(14),
        }
    } else {
        None
    };

    match crate::modules::load_module(image, params.as_deref()) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(8),
    }
}

pub fn handle_delete_module(name: u64, flags: u32) -> SyscallResult {
    if name == 0 {
        return errno(22);
    }

    let module_name = match crate::syscall::dispatch::util::parse_string_from_user(name, 256) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let force = (flags & 1) != 0;

    match crate::modules::unload_module(&module_name, force) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(16),
    }
}

pub fn handle_finit_module(fd: i32, param_values: u64, _flags: i32) -> SyscallResult {
    if fd < 0 {
        return errno(9);
    }

    let path = match crate::fs::fd::fd_get_path(fd) {
        Ok(p) => p,
        Err(_) => return errno(9),
    };
    let file_size = crate::fs::ramfs::NONOS_FILESYSTEM
        .get_file_info(&path)
        .map(|info| info.size)
        .unwrap_or(0);

    if file_size == 0 || file_size > 64 * 1024 * 1024 {
        return errno(22);
    }

    let mut image = alloc::vec![0u8; file_size];
    match crate::fs::fd::fd_read(fd, image.as_mut_ptr(), file_size) {
        Ok(n) if n == file_size => {}
        Ok(_) => return errno(5),
        Err(_) => return errno(9),
    }

    let params = if param_values != 0 {
        match crate::syscall::dispatch::util::parse_string_from_user(param_values, 4096) {
            Ok(s) => Some(s),
            Err(_) => return errno(14),
        }
    } else {
        None
    };

    match crate::modules::load_module(&image, params.as_deref()) {
        Ok(_) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(8),
    }
}

pub fn handle_acct(filename: u64) -> SyscallResult {
    if filename == 0 {
        crate::process::disable_accounting();
        return SyscallResult { value: 0, capability_consumed: false, audit_required: true };
    }

    let path = match crate::syscall::dispatch::util::parse_string_from_user(filename, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::process::enable_accounting(&path) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(13),
    }
}

pub fn handle_swapon(_path: u64, _swapflags: i32) -> SyscallResult {
    errno(38)
}

pub fn handle_swapoff(_path: u64) -> SyscallResult {
    errno(38)
}

pub fn handle_quotactl(_cmd: u32, _special: u64, _id: i32, _addr: u64) -> SyscallResult {
    errno(38)
}
