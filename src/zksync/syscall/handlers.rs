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
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if tx_ptr == 0 || tx_len == 0 || tx_len > 65536 { return errno(EINVAL); }
    let mut tx_data = alloc::vec![0u8; tx_len as usize];
    if copy_from_user(tx_ptr, &mut tx_data).is_err() { return errno(EFAULT); }
    if tx_data.len() < 85 { return errno(EINVAL); }
    let hash = crate::crypto::sha256(&tx_data);
    result_ok(i64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8])))
}

pub fn handle_zksync_get_tx_status(hash_ptr: u64, status_out: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if hash_ptr == 0 || status_out == 0 { return errno(EINVAL); }
    let mut hash = [0u8; 32];
    if copy_from_user(hash_ptr, &mut hash).is_err() { return errno(EFAULT); }
    let status: u64 = 0;
    if copy_to_user(status_out, &status.to_le_bytes()).is_err() { return errno(EFAULT); }
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
    let empty_result = [0u8; 32];
    if copy_to_user(result_out, &empty_result).is_err() { return errno(EFAULT); }
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
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if deposit_ptr == 0 || deposit_len < 72 { return errno(EINVAL); }
    let mut deposit_data = [0u8; 72];
    if copy_from_user(deposit_ptr, &mut deposit_data).is_err() { return errno(EFAULT); }
    let hash = crate::crypto::sha256(&deposit_data);
    result_ok(i64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8])))
}

pub fn handle_zksync_bridge_withdraw(withdraw_ptr: u64, withdraw_len: u64) -> SyscallResult {
    if !crate::zksync::is_initialized() { return errno(ENOSYS); }
    if withdraw_ptr == 0 || withdraw_len < 72 { return errno(EINVAL); }
    let mut withdraw_data = [0u8; 72];
    if copy_from_user(withdraw_ptr, &mut withdraw_data).is_err() { return errno(EFAULT); }
    let hash = crate::crypto::sha256(&withdraw_data);
    result_ok(i64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8])))
}
