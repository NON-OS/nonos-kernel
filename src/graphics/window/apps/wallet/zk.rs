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

use super::zk_circuit::*;
pub(crate) use super::zk_prove::{
    prove_balance_ownership, prove_stealth_spend_key, verify_wallet_proof,
};
pub(crate) use super::zk_types::*;
use crate::zk_engine::groth16::Groth16Prover;
use crate::zk_engine::ZKError;
use core::sync::atomic::Ordering;

pub(crate) fn init_wallet_zk() -> Result<(), ZKError> {
    if ZK_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    let mut k = ZK_KEYS.lock();
    let (pk, vk) = Groth16Prover::generate_keys(&build_balance_ownership_circuit()?)?;
    k.balance_ownership_pk = Some(pk);
    k.balance_ownership_vk = Some(vk);
    let (pk, vk) = Groth16Prover::generate_keys(&build_stealth_spend_circuit()?)?;
    k.stealth_pk = Some(pk);
    k.stealth_vk = Some(vk);
    drop(k);
    ZK_INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}
