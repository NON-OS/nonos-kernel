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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::crypto::ethereum::{Transaction, gwei_to_wei};
use crate::crypto::hash::blake3_hash;

use super::constants::{GAS_PRICE_GWEI, MAINNET_CHAIN_ID};
use super::types::{CapsuleCategory, CapsuleMetadata, InstallState, InstallationTask, InstalledCapsule};
use super::state::CAPSULE_STORE;

pub fn request_install(name: &str) -> Result<InstallationTask, &'static str> {
    let lock = CAPSULE_STORE.lock();
    let store = lock.as_ref().ok_or("Store not initialized")?;

    let id = blake3_hash(name.as_bytes());

    if store.installed.read().contains_key(&id) {
        return Err("Already installed");
    }

    let meta = store.available.read().get(&id).cloned().ok_or("Capsule not found")?;

    let state = if meta.nox_fee > 0 {
        InstallState::PaymentRequired
    } else {
        InstallState::Installing
    };

    let task = InstallationTask {
        capsule_id: id,
        state,
        tx_hash: None,
        progress_percent: 0,
        error: None,
    };

    store.pending_installs.write().insert(id, task.clone());

    if meta.nox_fee == 0 {
        drop(lock);
        complete_install(&id)?;
    }

    Ok(task)
}

pub fn create_payment_tx(capsule_id: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
    let lock = CAPSULE_STORE.lock();
    let store = lock.as_ref().ok_or("Store not initialized")?;

    let meta = store.available.read().get(capsule_id).cloned().ok_or("Capsule not found")?;

    if meta.nox_fee == 0 {
        return Err("No payment required");
    }

    let wallet = store.wallet.read();
    let wallet = wallet.as_ref().ok_or("Wallet not configured")?;

    let nonce = store.nonce.fetch_add(1, Ordering::SeqCst);

    let tx = Transaction::new_nox_transfer(
        store.fee_receiver.clone(),
        meta.nox_fee,
        nonce,
        gwei_to_wei(GAS_PRICE_GWEI),
        MAINNET_CHAIN_ID,
    );

    let signed = wallet.sign_transaction(&tx).ok_or("Signing failed")?;

    let mut pending = store.pending_installs.write();
    if let Some(task) = pending.get_mut(capsule_id) {
        task.state = InstallState::PaymentSubmitted;
    }

    Ok(signed.to_hex())
}

pub fn confirm_payment(capsule_id: &[u8; 32], tx_hash: [u8; 32]) -> Result<(), &'static str> {
    let lock = CAPSULE_STORE.lock();
    let store = lock.as_ref().ok_or("Store not initialized")?;

    let mut pending = store.pending_installs.write();
    let task = pending.get_mut(capsule_id).ok_or("No pending installation")?;

    task.tx_hash = Some(tx_hash);
    task.state = InstallState::PaymentConfirmed;

    drop(pending);
    drop(lock);

    complete_install(capsule_id)
}

pub fn complete_install(capsule_id: &[u8; 32]) -> Result<(), &'static str> {
    let lock = CAPSULE_STORE.lock();
    let store = lock.as_ref().ok_or("Store not initialized")?;

    let meta = store.available.read().get(capsule_id).cloned().ok_or("Capsule not found")?;

    {
        let mut pending = store.pending_installs.write();
        if let Some(task) = pending.get_mut(capsule_id) {
            task.state = InstallState::Installing;
            task.progress_percent = 50;
        }
    }

    let installed = InstalledCapsule {
        metadata: meta,
        install_timestamp: crate::time::timestamp_millis(),
        code_hash: *capsule_id,
        active: AtomicBool::new(true),
    };

    store.installed.write().insert(*capsule_id, installed);

    {
        let mut pending = store.pending_installs.write();
        if let Some(task) = pending.get_mut(capsule_id) {
            task.state = InstallState::Installed;
            task.progress_percent = 100;
        }
    }

    Ok(())
}

pub fn uninstall(capsule_id: &[u8; 32]) -> Result<(), &'static str> {
    let lock = CAPSULE_STORE.lock();
    let store = lock.as_ref().ok_or("Store not initialized")?;

    let meta = store.installed.read().get(capsule_id).map(|c| c.metadata.category);
    if meta == Some(CapsuleCategory::System) {
        return Err("Cannot uninstall system capsule");
    }

    store.installed.write().remove(capsule_id);
    Ok(())
}

pub fn get_install_status(capsule_id: &[u8; 32]) -> Option<InstallationTask> {
    let lock = CAPSULE_STORE.lock();
    match lock.as_ref() {
        Some(store) => store.pending_installs.read().get(capsule_id).cloned(),
        None => None,
    }
}

pub fn register_capsule(meta: CapsuleMetadata) -> Result<(), &'static str> {
    if meta.signature == [0u8; 64] {
        return Err("Invalid signature");
    }

    let code_hash = meta.id;
    if !crate::crypto::verify_signature(&code_hash, &meta.signature, &meta.ed25519_pubkey) {
        return Err("Signature verification failed");
    }

    let lock = CAPSULE_STORE.lock();
    let store = lock.as_ref().ok_or("Store not initialized")?;

    store.available.write().insert(meta.id, meta);
    Ok(())
}
