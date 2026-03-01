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

use alloc::collections::BTreeMap;
use spin::RwLock;

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;

static CHILD_EXIT_STATUS: RwLock<BTreeMap<u32, (u32, i32)>> = RwLock::new(BTreeMap::new());

pub fn record_child_exit(parent_pid: u32, child_pid: u32, status: i32) {
    CHILD_EXIT_STATUS.write().insert(child_pid, (parent_pid, status));
}

pub fn handle_wait4(pid: i64, wstatus: u64, options: u64, rusage: u64) -> SyscallResult {
    const WNOHANG: u64 = 1;

    let current_pid = match crate::process::current_pid() {
        Some(p) => p,
        None => return errno(1),
    };

    loop {
        let mut exit_map = CHILD_EXIT_STATUS.write();

        let mut found_child: Option<(u32, i32)> = None;

        for (child_pid, (parent, status)) in exit_map.iter() {
            if *parent != current_pid {
                continue;
            }

            match pid {
                -1 => {
                    found_child = Some((*child_pid, *status));
                    break;
                }
                0 => {
                    found_child = Some((*child_pid, *status));
                    break;
                }
                p if p > 0 => {
                    if *child_pid == p as u32 {
                        found_child = Some((*child_pid, *status));
                        break;
                    }
                }
                _ => {
                    found_child = Some((*child_pid, *status));
                    break;
                }
            }
        }

        if let Some((child_pid, status)) = found_child {
            exit_map.remove(&child_pid);

            if wstatus != 0 {
                let encoded_status = if status >= 0 {
                    (status << 8) & 0xFF00
                } else {
                    status & 0x7F
                };
                unsafe {
                    core::ptr::write(wstatus as *mut i32, encoded_status);
                }
            }

            if rusage != 0 {
                unsafe {
                    core::ptr::write_bytes(rusage as *mut u8, 0, 144);
                }
            }

            return SyscallResult {
                value: child_pid as i64,
                capability_consumed: false,
                audit_required: false
            };
        }

        drop(exit_map);

        if (options & WNOHANG) != 0 {
            return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
        }

        crate::sched::yield_cpu();
    }
}

pub fn handle_waitid(idtype: u64, id: u64, infop: u64, options: u64, rusage: u64) -> SyscallResult {
    const P_ALL: u64 = 0;
    const P_PID: u64 = 1;
    const P_PGID: u64 = 2;

    const WEXITED: u64 = 4;
    const WSTOPPED: u64 = 2;
    const WCONTINUED: u64 = 8;
    const WNOHANG: u64 = 1;
    const WNOWAIT: u64 = 0x01000000;

    if infop == 0 {
        return errno(14);
    }

    let _wait_pid: i64 = match idtype {
        P_ALL => -1,
        P_PID => id as i64,
        P_PGID => -(id as i64),
        _ => return errno(22),
    };

    if (options & (WEXITED | WSTOPPED | WCONTINUED)) == 0 {
        return errno(22);
    }

    let process_table = crate::process::get_process_table();
    let current_pid = crate::process::current_pid().unwrap_or(1);

    loop {
        let mut found_child = None;

        for child in process_table.get_children_of(current_pid) {
            let matches = match idtype {
                P_ALL => true,
                P_PID => child.pid == id as u32,
                P_PGID => child.process_group() == id as u32,
                _ => false,
            };

            if matches {
                let state = child.state.lock();
                let state_matches = match *state {
                    crate::process::nonos_core::ProcessState::Zombie(_) if (options & WEXITED) != 0 => true,
                    crate::process::nonos_core::ProcessState::Stopped if (options & WSTOPPED) != 0 => true,
                    crate::process::nonos_core::ProcessState::Ready if (options & WCONTINUED) != 0 => true,
                    _ => false,
                };

                if state_matches {
                    found_child = Some((child.pid, *state, child.exit_status()));
                    break;
                }
            }
        }

        if let Some((pid, state, exit_status)) = found_child {
            unsafe {
                let info = infop as *mut u8;
                core::ptr::write_bytes(info, 0, 128);

                core::ptr::write((info) as *mut i32, 17);
                core::ptr::write((info.add(8)) as *mut i32, match state {
                    crate::process::nonos_core::ProcessState::Zombie(_) => 1,
                    crate::process::nonos_core::ProcessState::Stopped => 5,
                    _ => 6,
                });
                core::ptr::write((info.add(12)) as *mut i32, pid as i32);
                core::ptr::write((info.add(16)) as *mut i32, 0);
                core::ptr::write((info.add(20)) as *mut i32, exit_status);
            }

            if (options & WNOWAIT) == 0 {
                if matches!(state, crate::process::nonos_core::ProcessState::Zombie(_)) {
                    let _ = process_table.terminate_process(pid);
                }
            }

            if rusage != 0 {
                unsafe {
                    core::ptr::write_bytes(rusage as *mut u8, 0, 144);
                }
            }

            return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
        }

        if (options & WNOHANG) != 0 {
            unsafe {
                core::ptr::write_bytes(infop as *mut u8, 0, 128);
            }
            return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
        }

        if !process_table.has_children(current_pid) {
            return errno(10);
        }

        crate::sched::yield_cpu();
    }
}
