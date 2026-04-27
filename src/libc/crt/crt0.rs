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

use core::ptr;

pub type MainFn = extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;

#[repr(C)]
pub struct StartupInfo {
    pub argc: i32,
    pub argv: *const *const u8,
    pub envp: *const *const u8,
    pub auxv: *const AuxVal,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuxVal {
    pub a_type: usize,
    pub a_val: usize,
}

pub const AT_NULL: usize = 0;
pub const AT_PHDR: usize = 3;
pub const AT_PHENT: usize = 4;
pub const AT_PHNUM: usize = 5;
pub const AT_PAGESZ: usize = 6;
pub const AT_ENTRY: usize = 9;
pub const AT_UID: usize = 11;
pub const AT_EUID: usize = 12;
pub const AT_GID: usize = 13;
pub const AT_EGID: usize = 14;
pub const AT_RANDOM: usize = 25;

pub fn crt0_start(stack_ptr: *const usize, main: MainFn) -> ! {
    let info = setup_stack(stack_ptr);
    super::crti::crti_init();
    let ret = call_main(main, &info);
    super::crti::crti_fini();
    crate::libc::unistd::_exit(ret);
}

pub fn setup_stack(sp: *const usize) -> StartupInfo {
    unsafe {
        let argc = *sp as i32;
        let argv = sp.add(1) as *const *const u8;
        let mut envp_idx = 1 + argc as usize + 1;
        while *sp.add(envp_idx) != 0 {
            envp_idx += 1;
        }
        let envp = sp.add(1 + argc as usize + 1) as *const *const u8;
        let auxv = sp.add(envp_idx + 1) as *const AuxVal;
        StartupInfo { argc, argv, envp, auxv }
    }
}

pub fn call_main(main: MainFn, info: &StartupInfo) -> i32 {
    main(info.argc, info.argv, info.envp)
}

pub fn get_auxval(auxv: *const AuxVal, typ: usize) -> Option<usize> {
    unsafe {
        let mut p = auxv;
        while (*p).a_type != AT_NULL {
            if (*p).a_type == typ {
                return Some((*p).a_val);
            }
            p = p.add(1);
        }
        None
    }
}

pub fn init_tls(info: &StartupInfo) -> Result<(), i32> {
    if let Some(random) = get_auxval(info.auxv, AT_RANDOM) {
        let canary = unsafe { ptr::read(random as *const u64) };
        crate::libc::pthread::tls::set_stack_canary(canary);
    }
    Ok(())
}
