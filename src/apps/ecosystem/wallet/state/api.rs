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
use super::super::keys::{SecureSecretKey, WalletKeys};
use super::super::stealth::StealthKeyPair;
use super::account::AccountInfo;
use super::types::{Network, WalletState};
use crate::crypto::CryptoError;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU8, Ordering};
use spin::RwLock;

pub(super) static WALLET_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(super) static WALLET_LOCKED: AtomicBool = AtomicBool::new(true);
pub(super) static WALLET_STATE: RwLock<Option<WalletStateInner>> = RwLock::new(None);
pub(super) static ACTIVE_ACCOUNT: AtomicU8 = AtomicU8::new(0);

pub(super) struct WalletStateInner {
    pub keys: WalletKeys,
    pub stealth_keys: Option<StealthKeyPair>,
    pub accounts: Vec<AccountInfo>,
    pub network: Network,
    pub password_hash: [u8; 32],
}

impl Drop for WalletStateInner {
    fn drop(&mut self) {
        for byte in self.password_hash.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

pub fn init_wallet(keys: WalletKeys, password: &[u8]) -> Result<(), CryptoError> {
    if WALLET_INITIALIZED.load(Ordering::SeqCst) {
        return Err(CryptoError::InvalidState);
    }
    let password_hash = crate::crypto::hash::sha256(password);
    let first_address = keys.derive_address(0)?;
    let first_account = AccountInfo::new(0, first_address);
    let inner = WalletStateInner {
        keys,
        stealth_keys: None,
        accounts: alloc::vec![first_account],
        network: Network::Sepolia,
        password_hash,
    };
    {
        let mut guard = WALLET_STATE.write();
        *guard = Some(inner);
    }
    WALLET_LOCKED.store(false, Ordering::SeqCst);
    WALLET_INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}

pub fn get_wallet() -> Option<WalletState> {
    if !WALLET_INITIALIZED.load(Ordering::SeqCst) {
        return None;
    }
    Some(WalletState::current())
}
pub fn lock_wallet() {
    WALLET_LOCKED.store(true, Ordering::SeqCst);
}

pub fn unlock_wallet(password: &[u8]) -> Result<(), CryptoError> {
    if !WALLET_INITIALIZED.load(Ordering::SeqCst) {
        return Err(CryptoError::InvalidState);
    }
    let password_hash = crate::crypto::hash::sha256(password);
    let guard = WALLET_STATE.read();
    let inner = guard.as_ref().ok_or(CryptoError::InvalidState)?;
    if password_hash != inner.password_hash {
        return Err(CryptoError::AuthenticationFailed);
    }
    drop(guard);
    WALLET_LOCKED.store(false, Ordering::SeqCst);
    Ok(())
}

pub fn is_locked() -> bool {
    WALLET_LOCKED.load(Ordering::SeqCst)
}
pub fn is_initialized() -> bool {
    WALLET_INITIALIZED.load(Ordering::SeqCst)
}
pub fn set_network(network: Network) {
    let mut guard = WALLET_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.network = network;
    }
}
pub fn get_network() -> Network {
    let guard = WALLET_STATE.read();
    guard.as_ref().map(|i| i.network).unwrap_or(Network::Mainnet)
}
pub fn set_active_account(index: u8) {
    ACTIVE_ACCOUNT.store(index, Ordering::Relaxed);
}
pub fn get_active_account() -> u8 {
    ACTIVE_ACCOUNT.load(Ordering::Relaxed)
}

pub fn add_account() -> Result<AccountInfo, CryptoError> {
    if WALLET_LOCKED.load(Ordering::SeqCst) {
        return Err(CryptoError::InvalidState);
    }
    let mut guard = WALLET_STATE.write();
    let inner = guard.as_mut().ok_or(CryptoError::InvalidState)?;
    let next_index = inner.accounts.len() as u32;
    let address = inner.keys.derive_address(next_index)?;
    let account = AccountInfo::new(next_index, address);
    inner.accounts.push(account.clone());
    Ok(account)
}

pub fn get_account(index: u32) -> Option<AccountInfo> {
    let guard = WALLET_STATE.read();
    let inner = guard.as_ref()?;
    inner.accounts.get(index as usize).cloned()
}
pub fn get_all_accounts() -> Vec<AccountInfo> {
    let guard = WALLET_STATE.read();
    match guard.as_ref() {
        Some(inner) => inner.accounts.clone(),
        None => Vec::new(),
    }
}
pub fn update_account_balance(index: u32, balance_wei: u128) {
    let mut guard = WALLET_STATE.write();
    if let Some(inner) = guard.as_mut() {
        if let Some(account) = inner.accounts.get_mut(index as usize) {
            account.balance_wei = balance_wei;
        }
    }
}
pub fn update_account_nonce(index: u32, nonce: u64) {
    let mut guard = WALLET_STATE.write();
    if let Some(inner) = guard.as_mut() {
        if let Some(account) = inner.accounts.get_mut(index as usize) {
            account.nonce = nonce;
        }
    }
}

pub fn get_secret_key(index: u32) -> Result<SecureSecretKey, CryptoError> {
    if WALLET_LOCKED.load(Ordering::SeqCst) {
        return Err(CryptoError::InvalidState);
    }
    let guard = WALLET_STATE.read();
    let inner = guard.as_ref().ok_or(CryptoError::InvalidState)?;
    Ok(SecureSecretKey::new(inner.keys.derive_secret_key(index)?))
}

pub fn set_stealth_keys(stealth_keys: StealthKeyPair) {
    let mut guard = WALLET_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.stealth_keys = Some(stealth_keys);
    }
}
pub fn get_stealth_keys() -> Option<StealthKeyPair> {
    let guard = WALLET_STATE.read();
    guard.as_ref().and_then(|i| i.stealth_keys.clone())
}

pub fn destroy_wallet() {
    let mut guard = WALLET_STATE.write();
    *guard = None;
    drop(guard);
    WALLET_LOCKED.store(true, Ordering::SeqCst);
    WALLET_INITIALIZED.store(false, Ordering::SeqCst);
    ACTIVE_ACCOUNT.store(0, Ordering::Relaxed);
}
