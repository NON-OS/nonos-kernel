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
use crate::zk_engine::get_zk_engine;
use crate::zk_engine::syscalls::helpers::is_valid_user_ptr;
use crate::zk_engine::syscalls::params::ZKStatsUserspace;

pub fn sys_zk_get_stats(
    stats_ptr: usize,
    process: &ProcessControlBlock,
) -> Result<usize, &'static str> {
    if !is_valid_user_ptr(stats_ptr, core::mem::size_of::<ZKStatsUserspace>(), process) {
        return Err("Invalid stats pointer");
    }
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    let engine_stats = engine.get_stats();
    let total_proofs = engine_stats.proofs_generated.load(core::sync::atomic::Ordering::SeqCst);
    let total_verifications =
        engine_stats.proofs_verified.load(core::sync::atomic::Ordering::SeqCst);
    let total_proving_time =
        engine_stats.total_proving_time_ms.load(core::sync::atomic::Ordering::SeqCst);
    let total_verification_time =
        engine_stats.total_verification_time_ms.load(core::sync::atomic::Ordering::SeqCst);
    let user_stats = ZKStatsUserspace {
        proofs_generated: total_proofs,
        proofs_verified: total_verifications,
        verification_failures: engine_stats
            .verification_failures
            .load(core::sync::atomic::Ordering::SeqCst),
        circuits_compiled: engine_stats
            .circuits_compiled
            .load(core::sync::atomic::Ordering::SeqCst),
        avg_proving_time_ms: if total_proofs > 0 { total_proving_time / total_proofs } else { 0 },
        avg_verification_time_ms: if total_verifications > 0 {
            total_verification_time / total_verifications
        } else {
            0
        },
    };
    unsafe {
        *(stats_ptr as *mut ZKStatsUserspace) = user_stats;
    }
    Ok(0)
}
