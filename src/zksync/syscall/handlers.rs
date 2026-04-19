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
use crate::syscall::dispatch::errno;
use crate::usercopy::{copy_from_user, copy_to_user};
use crate::zksync::types::U256;

const ENOSYS: i32 = 38;
const EPERM: i32 = 1;
const EINVAL: i32 = 22;
const EFAULT: i32 = 14;

fn result_ok(value: i64) -> SyscallResult {
    SyscallResult { value, capability_consumed: false, audit_required: true }
}

pub fn handle_zksync_submit_tx(tx_ptr: u64, tx_len: u64) -> SyscallResult {
    use crate::zksync::types::{L2Transaction, TxHash, Address, Nonce, Gas};
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if tx_ptr == 0 || tx_len == 0 || tx_len > 65536 { return errno(EINVAL); }
    let mut tx_data = alloc::vec![0u8; tx_len as usize];
    if copy_from_user(tx_ptr, &mut tx_data).is_err() { return errno(EFAULT); }
    if tx_data.len() < 85 { return errno(EINVAL); }
    let hash_bytes = crate::crypto::sha256(&tx_data);
    let hash = TxHash(hash_bytes);
    let from = Address(tx_data[0..20].try_into().unwrap_or([0; 20]));
    let to_bytes: [u8; 20] = tx_data[20..40].try_into().unwrap_or([0; 20]);
    let to = if to_bytes == [0u8; 20] { None } else { Some(Address(to_bytes)) };
    let nonce_val = u64::from_le_bytes(tx_data[40..48].try_into().unwrap_or([0; 8]));
    let value_bytes: [u8; 32] = tx_data[48..80].try_into().unwrap_or([0; 32]);
    let gas_limit_val = if tx_data.len() >= 88 {
        u64::from_le_bytes(tx_data[80..88].try_into().unwrap_or([0; 8]))
    } else { 1000000 };
    let tx = L2Transaction {
        hash, from, to, nonce: Nonce(nonce_val),
        value: U256::from_bytes_be(&value_bytes),
        data: if tx_data.len() > 88 { tx_data[88..].to_vec() } else { alloc::vec![] },
        gas_limit: Gas(gas_limit_val),
        max_fee_per_gas: U256::ZERO, max_priority_fee_per_gas: U256::ZERO,
        signature: crate::zksync::types::TransactionSignature::default(),
    };
    if crate::zksync::global::submit_transaction(tx) {
        result_ok(i64::from_le_bytes(hash_bytes[..8].try_into().unwrap_or([0; 8])))
    } else {
        errno(EINVAL)
    }
}

pub fn handle_zksync_get_tx_status(hash_ptr: u64, status_out: u64) -> SyscallResult {
    use crate::zksync::types::{TxHash, TransactionStatus};
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if hash_ptr == 0 || status_out == 0 { return errno(EINVAL); }
    let mut hash = [0u8; 32];
    if copy_from_user(hash_ptr, &mut hash).is_err() { return errno(EFAULT); }
    let status_code: u64 = match crate::zksync::global::get_tx_status(&TxHash(hash)) {
        Some(TransactionStatus::Pending) => 0,
        Some(TransactionStatus::Included { .. }) => 1,
        Some(TransactionStatus::Committed { .. }) => 2,
        Some(TransactionStatus::Proven { .. }) => 3,
        Some(TransactionStatus::Finalized { .. }) => 4,
        Some(TransactionStatus::Failed { .. }) => 5,
        None => 6,
    };
    if copy_to_user(status_out, &status_code.to_le_bytes()).is_err() { return errno(EFAULT); }
    result_ok(0)
}

pub fn handle_zksync_get_balance(addr_ptr: u64, balance_out: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if addr_ptr == 0 || balance_out == 0 { return errno(EINVAL); }
    let mut addr_bytes = [0u8; 20];
    if copy_from_user(addr_ptr, &mut addr_bytes).is_err() { return errno(EFAULT); }
    let address = crate::zksync::types::Address(addr_bytes);
    let balance = crate::zksync::global::with_state(|state| state.get_balance(&address))
        .unwrap_or(U256::ZERO);
    let balance_bytes = balance.to_bytes_be();
    if copy_to_user(balance_out, &balance_bytes).is_err() { return errno(EFAULT); }
    result_ok(0)
}

pub fn handle_zksync_get_nonce(addr_ptr: u64, nonce_out: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if addr_ptr == 0 || nonce_out == 0 { return errno(EINVAL); }
    let mut addr_bytes = [0u8; 20];
    if copy_from_user(addr_ptr, &mut addr_bytes).is_err() { return errno(EFAULT); }
    let address = crate::zksync::types::Address(addr_bytes);
    let nonce = crate::zksync::global::with_state(|state| state.get_nonce(&address).0)
        .unwrap_or(0);
    if copy_to_user(nonce_out, &nonce.to_le_bytes()).is_err() { return errno(EFAULT); }
    result_ok(0)
}

pub fn handle_zksync_call(call_ptr: u64, call_len: u64, result_out: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if call_ptr == 0 || call_len == 0 || result_out == 0 { return errno(EINVAL); }
    if call_len > 131072 { return errno(EINVAL); }
    let mut call_data = alloc::vec![0u8; call_len as usize];
    if copy_from_user(call_ptr, &mut call_data).is_err() { return errno(EFAULT); }
    if call_data.len() < 24 { return errno(EINVAL); }
    let target = crate::zksync::types::Address(call_data[0..20].try_into().unwrap_or([0; 20]));
    let selector = if call_data.len() >= 24 {
        u32::from_be_bytes(call_data[20..24].try_into().unwrap_or([0; 4]))
    } else { 0 };
    let call_result = match selector {
        0x70a08231 => {
            let addr_bytes: [u8; 20] = if call_data.len() >= 56 {
                call_data[36..56].try_into().unwrap_or([0; 20])
            } else { [0; 20] };
            let query_addr = crate::zksync::types::Address(addr_bytes);
            let balance = crate::zksync::global::with_state(|s| s.get_balance(&query_addr))
                .unwrap_or(U256::ZERO);
            balance.to_bytes_be()
        }
        0x54fd4d50 => {
            let mut version = [0u8; 32];
            version[31] = 1;
            version
        }
        _ => {
            if call_data.len() >= 56 {
                let slot_bytes: [u8; 32] = call_data[24..56].try_into().unwrap_or([0; 32]);
                let slot = U256::from_bytes_be(&slot_bytes);
                let value = crate::zksync::global::get_storage_value(&target, &slot);
                value.to_bytes_be()
            } else { [0u8; 32] }
        }
    };
    if copy_to_user(result_out, &call_result).is_err() { return errno(EFAULT); }
    result_ok(32)
}

pub fn handle_zksync_estimate_gas(tx_ptr: u64, tx_len: u64, gas_out: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if tx_ptr == 0 || tx_len == 0 || gas_out == 0 { return errno(EINVAL); }
    let base_gas: u64 = 21000;
    let data_gas = (tx_len as u64).saturating_mul(16);
    let total_gas = base_gas.saturating_add(data_gas);
    if copy_to_user(gas_out, &total_gas.to_le_bytes()).is_err() { return errno(EFAULT); }
    result_ok(0)
}

pub fn handle_zksync_get_block(block_num: u64, block_out: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if block_out == 0 { return errno(EINVAL); }
    let current_block = crate::zksync::global::with_state(|s| s.current_block().0).unwrap_or(0);
    if block_num > current_block { return errno(EINVAL); }
    let state_root = crate::zksync::global::with_state(|s| s.state_root()).unwrap_or([0u8; 32]);
    let mut block_data = [0u8; 128];
    block_data[..8].copy_from_slice(&block_num.to_le_bytes());
    block_data[8..16].copy_from_slice(&current_block.to_le_bytes());
    block_data[16..48].copy_from_slice(&state_root);
    if copy_to_user(block_out, &block_data).is_err() { return errno(EFAULT); }
    result_ok(128)
}

pub fn handle_zksync_get_batch(batch_num: u64, batch_out: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if batch_out == 0 { return errno(EINVAL); }
    let current_batch = crate::zksync::global::with_state(|s| s.current_batch().0).unwrap_or(0);
    if batch_num > current_batch { return errno(EINVAL); }
    let state_root = crate::zksync::global::with_state(|s| s.state_root()).unwrap_or([0u8; 32]);
    let mut batch_data = [0u8; 96];
    batch_data[..8].copy_from_slice(&batch_num.to_le_bytes());
    batch_data[8..16].copy_from_slice(&current_batch.to_le_bytes());
    batch_data[16..48].copy_from_slice(&state_root);
    if copy_to_user(batch_out, &batch_data).is_err() { return errno(EFAULT); }
    result_ok(96)
}

pub fn handle_zksync_prove_batch(_batch_num: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    errno(EPERM)
}

pub fn handle_zksync_get_proof(batch_num: u64, proof_out: u64, proof_len: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if proof_out == 0 || proof_len < 256 { return errno(EINVAL); }
    let mut proof = alloc::vec![0u8; 256];
    proof[..8].copy_from_slice(&batch_num.to_le_bytes());
    if copy_to_user(proof_out, &proof[..proof_len.min(256) as usize]).is_err() { return errno(EFAULT); }
    result_ok(256)
}

pub fn handle_zksync_bridge_deposit(deposit_ptr: u64, deposit_len: u64) -> SyscallResult {
    use crate::zksync::bridge::deposit::Deposit;
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if deposit_ptr == 0 || deposit_len < 72 { return errno(EINVAL); }
    let mut deposit_data = [0u8; 72];
    if copy_from_user(deposit_ptr, &mut deposit_data).is_err() { return errno(EFAULT); }
    let l1_tx_hash: [u8; 32] = deposit_data[0..32].try_into().unwrap_or([0; 32]);
    let recipient = crate::zksync::types::Address(deposit_data[32..52].try_into().unwrap_or([0; 20]));
    let amount_bytes: [u8; 32] = if deposit_len >= 84 {
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&deposit_data[52..72]);
        padded
    } else {
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&deposit_data[52..72]);
        padded
    };
    let amount = U256::from_bytes_be(&amount_bytes);
    let l1_block = if deposit_len >= 80 {
        u64::from_le_bytes(deposit_data[72..80].try_into().unwrap_or([0; 8]))
    } else { 0 };
    let deposit = Deposit { l1_tx_hash, recipient, amount, l1_block };
    crate::zksync::global::queue_deposit(deposit);
    if let Some(processed) = crate::zksync::global::process_deposit() {
        let hash = crate::crypto::sha256(&processed.l1_tx_hash);
        result_ok(i64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8])))
    } else {
        let hash = crate::crypto::sha256(&deposit_data);
        result_ok(i64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8])))
    }
}

pub fn handle_zksync_bridge_withdraw(withdraw_ptr: u64, withdraw_len: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if withdraw_ptr == 0 || withdraw_len < 72 { return errno(EINVAL); }
    let mut withdraw_data = [0u8; 72];
    if copy_from_user(withdraw_ptr, &mut withdraw_data).is_err() { return errno(EFAULT); }
    let sender = crate::zksync::types::Address(withdraw_data[0..20].try_into().unwrap_or([0; 20]));
    let recipient = crate::zksync::types::Address(withdraw_data[20..40].try_into().unwrap_or([0; 20]));
    let amount_bytes: [u8; 32] = withdraw_data[40..72].try_into().unwrap_or([0; 32]);
    let amount = U256::from_bytes_be(&amount_bytes);
    match crate::zksync::global::initiate_withdrawal(sender, recipient, amount) {
        Some(msg_hash) => {
            result_ok(i64::from_le_bytes(msg_hash[..8].try_into().unwrap_or([0; 8])))
        }
        None => errno(EINVAL)
    }
}
