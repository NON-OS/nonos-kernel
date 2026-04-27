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

use super::compile::sys_zk_compile_circuit;
use super::prove::sys_zk_prove;
use super::stats::sys_zk_get_stats;
use super::verify::sys_zk_verify;
use crate::process::core::ProcessControlBlock;
use crate::zk_engine::syscalls::helpers::check_zk_permissions;
use crate::zk_engine::syscalls::params::*;

pub fn handle_zk_syscall(
    syscall_num: usize,
    arg1: usize,
    _arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    process: &ProcessControlBlock,
) -> Result<usize, &'static str> {
    if !check_zk_permissions(process) {
        return Err("Process lacks ZK permissions");
    }

    match syscall_num {
        SYS_ZK_PROVE => sys_zk_prove(arg1, process),
        SYS_ZK_VERIFY => sys_zk_verify(arg1, process),
        SYS_ZK_COMPILE_CIRCUIT => sys_zk_compile_circuit(arg1, process),
        SYS_ZK_GET_STATS => sys_zk_get_stats(arg1, process),
        _ => Err("Invalid ZK syscall number"),
    }
}
