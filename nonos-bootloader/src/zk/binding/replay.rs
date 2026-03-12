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

/*
 * ZK Replay Protection
 *
 * Every proof must be bound to:
 * 1. kernel_hash   - the specific kernel binary being attested
 * 2. boot_nonce    - fresh entropy per boot session (prevents replay)
 * 3. timestamp     - boot time (allows time-based expiry checks)
 * 4. machine_id    - TPM EK-derived ID (ties proof to specific hardware)
 *
 * Without all four bindings, an attacker could replay a captured proof
 * on a different machine or boot session.
 */

use spin::Mutex;

const DS_MACHINE_ID: &str = "NONOS:MACHINE:ID:v1";
const DS_NONCE_COMMIT: &str = "NONOS:NONCE:COMMIT:v1";

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZkPublicInputs {
    pub kernel_hash: [u8; 32],
    pub boot_nonce: [u8; 32],
    pub timestamp: u64,
    pub machine_id: [u8; 32],
}

impl ZkPublicInputs {
    pub fn to_bytes(&self) -> [u8; 104] {
        let mut buf = [0u8; 104];
        buf[0..32].copy_from_slice(&self.kernel_hash);
        buf[32..64].copy_from_slice(&self.boot_nonce);
        buf[64..72].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[72..104].copy_from_slice(&self.machine_id);
        buf
    }
}

static BOOT_NONCE: Mutex<Option<[u8; 32]>> = Mutex::new(None);
static MACHINE_ID: Mutex<Option<[u8; 32]>> = Mutex::new(None);

pub fn init_boot_nonce(entropy: &[u8; 64]) {
    let mut h = blake3::Hasher::new_derive_key(DS_NONCE_COMMIT);
    h.update(entropy);
    let nonce = *h.finalize().as_bytes();

    let mut guard = BOOT_NONCE.lock();
    *guard = Some(nonce);
}

pub fn get_boot_nonce() -> [u8; 32] {
    let guard = BOOT_NONCE.lock();
    guard.expect("boot nonce not initialized")
}

pub fn is_nonce_initialized() -> bool {
    let guard = BOOT_NONCE.lock();
    guard.is_some()
}

pub fn derive_machine_id(tpm_ek_public: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DS_MACHINE_ID);
    h.update(tpm_ek_public);
    *h.finalize().as_bytes()
}

pub fn init_machine_id(tpm_ek_public: &[u8]) {
    let id = derive_machine_id(tpm_ek_public);
    let mut guard = MACHINE_ID.lock();
    *guard = Some(id);
}

pub fn get_machine_id() -> [u8; 32] {
    let guard = MACHINE_ID.lock();
    guard.unwrap_or([0u8; 32])
}

pub fn is_machine_id_initialized() -> bool {
    let guard = MACHINE_ID.lock();
    guard.is_some()
}

pub fn build_public_inputs(kernel_hash: [u8; 32], timestamp: u64) -> ZkPublicInputs {
    ZkPublicInputs {
        kernel_hash,
        boot_nonce: get_boot_nonce(),
        timestamp,
        machine_id: get_machine_id(),
    }
}

pub fn verify_nonce_freshness(claimed_nonce: &[u8; 32]) -> bool {
    let guard = BOOT_NONCE.lock();
    match *guard {
        Some(ref current) => {
            let mut x = 0u8;
            for i in 0..32 {
                x |= current[i] ^ claimed_nonce[i];
            }
            x == 0
        }
        None => false,
    }
}

pub fn verify_machine_id(claimed_id: &[u8; 32]) -> bool {
    let guard = MACHINE_ID.lock();
    match *guard {
        Some(ref current) => {
            let mut x = 0u8;
            for i in 0..32 {
                x |= current[i] ^ claimed_id[i];
            }
            x == 0
        }
        None => true,
    }
}
