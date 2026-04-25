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

use crate::process::core::ProcessControlBlock;
use crate::zk_engine::syscalls::helpers::*;
use crate::zk_engine::syscalls::params::*;
use crate::zk_engine::{get_zk_engine, ZKError};
use core::slice;

pub fn sys_zk_compile_circuit(
    params_ptr: usize,
    process: &ProcessControlBlock,
) -> Result<usize, &'static str> {
    if !check_circuit_compilation_permissions(process) {
        return Err("Process lacks circuit compilation permissions");
    }
    if !is_valid_user_ptr(params_ptr, core::mem::size_of::<ZKCompileParams>(), process) {
        return Err("Invalid parameters pointer");
    }
    let params = unsafe { &*(params_ptr as *const ZKCompileParams) };
    if params.constraints_len > MAX_CONSTRAINTS * 64 {
        return Err("Too many constraints");
    }
    if params.num_witnesses > MAX_WITNESS_SIZE / 32 {
        return Err("Too many witnesses");
    }
    if !is_valid_user_ptr(params.constraints_ptr as usize, params.constraints_len, process) {
        return Err("Invalid constraints pointer");
    }
    if !is_valid_user_ptr(params.circuit_id_ptr as usize, core::mem::size_of::<u32>(), process) {
        return Err("Invalid circuit ID output pointer");
    }
    let constraints_data =
        unsafe { slice::from_raw_parts(params.constraints_ptr, params.constraints_len) };
    let constraints =
        deserialize_constraints(constraints_data).map_err(|_| "Invalid constraints format")?;
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    let start_time = crate::time::timestamp_millis();
    let circuit_id = match engine.compile_circuit(constraints, params.num_witnesses) {
        Ok(id) => id,
        Err(ZKError::InvalidCircuit) => return Err("Invalid circuit"),
        Err(ZKError::OutOfMemory) => return Err("Out of memory"),
        Err(_) => return Err("Circuit compilation failed"),
    };
    let compilation_time = crate::time::timestamp_millis() - start_time;
    unsafe {
        *(params.circuit_id_ptr) = circuit_id;
    }
    crate::log::info!(
        "Process {} compiled circuit {} in {}ms",
        process.pid,
        circuit_id,
        compilation_time
    );
    process.zk_circuits_compiled.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Ok(0)
}
