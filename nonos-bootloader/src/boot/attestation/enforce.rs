// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use uefi::prelude::*;

use super::binding::{verify_commitment_binding, verify_kernel_in_proof};
use crate::display::{log_error as panel_error, show_error_screen};
use crate::log::logger::log_error;
use crate::zk::binding::compute_capsule_commitment;
use crate::zk::{parse_zk_proof, BootAttestationResult};

use super::super::util::fatal_reset;

pub fn enforce_zk_binding(
    st: &mut SystemTable<Boot>,
    result: &BootAttestationResult,
    kernel_bytes: &[u8],
    actual_kernel_hash: &[u8; 32],
    gop_available: bool,
) {
    let (proof_block, _) = match parse_zk_proof(kernel_bytes) {
        Ok(pb) => pb,
        Err(e) => {
            log_error("zk_bind", "Failed to parse proof for binding check");
            log_error("zk_bind", e);
            binding_failure(st, gop_available, e);
        }
    };

    if let Err(e) = verify_kernel_in_proof(result, actual_kernel_hash, &proof_block) {
        log_error("zk_bind", e);
        binding_failure(st, gop_available, e);
    }

    let expected = compute_capsule_commitment(
        actual_kernel_hash,
        &proof_block.boot_nonce,
        &proof_block.machine_id,
        &proof_block.program_hash,
    );
    if let Err(e) = verify_commitment_binding(&result.capsule_commitment, &expected) {
        log_error("zk_bind", e);
        binding_failure(st, gop_available, e);
    }
}

fn binding_failure(st: &mut SystemTable<Boot>, gop: bool, msg: &'static str) -> ! {
    if gop {
        panel_error(b"ZK BINDING FAILED");
        show_error_screen(msg.as_bytes());
    }
    fatal_reset(st, msg);
}
