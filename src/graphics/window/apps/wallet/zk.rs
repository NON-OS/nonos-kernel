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

use core::sync::atomic::Ordering;

use crate::zk_engine::ZKError;
use crate::zk_engine::groth16::Groth16Prover;

pub(crate) use super::zk_types::*;
pub(crate) use super::zk_prove::prove_balance_ownership;
use super::zk_circuit::*;

pub(crate) fn init_wallet_zk() -> Result<(), ZKError> {
    if ZK_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut keys = ZK_KEYS.lock();

    let balance_circuit = build_balance_ownership_circuit()?;
    let (balance_pk, balance_vk) = Groth16Prover::generate_keys(&balance_circuit)?;
    keys.balance_ownership_pk = Some(balance_pk);
    keys.balance_ownership_vk = Some(balance_vk);

    let tx_circuit = build_transaction_auth_circuit()?;
    let (tx_pk, tx_vk) = Groth16Prover::generate_keys(&tx_circuit)?;
    keys.tx_auth_pk = Some(tx_pk);
    keys.tx_auth_vk = Some(tx_vk);

    let stealth_circuit = build_stealth_spend_circuit()?;
    let (stealth_pk, stealth_vk) = Groth16Prover::generate_keys(&stealth_circuit)?;
    keys.stealth_pk = Some(stealth_pk);
    keys.stealth_vk = Some(stealth_vk);

    let sufficiency_circuit = build_balance_sufficiency_circuit()?;
    let (suff_pk, suff_vk) = Groth16Prover::generate_keys(&sufficiency_circuit)?;
    keys.sufficiency_pk = Some(suff_pk);
    keys.sufficiency_vk = Some(suff_vk);

    drop(keys);
    ZK_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}
