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

use spin::Mutex;

use super::pcr::PcrIndex;
use super::quote::AttestationQuote;
use super::state::AttestationState;

pub static ATTESTATION_STATE: Mutex<AttestationState> = Mutex::new(AttestationState::new());

pub fn init_attestation() {
    let mut state = ATTESTATION_STATE.lock();
    state.init();
}

pub fn extend_pcr(index: PcrIndex, data: &[u8]) {
    let mut state = ATTESTATION_STATE.lock();
    state.extend_pcr(index, data);
}

pub fn extend_pcr_hash(index: PcrIndex, hash: &[u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.extend_pcr_hash(index, hash);
}

pub fn set_kernel_measurement(hash: [u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_kernel_hash(hash);
}

pub fn set_bootloader_measurement(hash: [u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_bootloader_hash(hash);
}

pub fn set_zk_attestation(verified: bool, program_hash: [u8; 32], commitment: [u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_zk_verified(verified, program_hash, commitment);
}

pub fn set_signature_attestation(verified: bool) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_signature_verified(verified);
}

pub fn generate_attestation_quote(nonce: [u8; 32], timestamp: u64) -> AttestationQuote {
    let state = ATTESTATION_STATE.lock();
    state.generate_quote(nonce, timestamp)
}

pub fn get_boot_measurement() -> [u8; 32] {
    let state = ATTESTATION_STATE.lock();
    state.compute_composite_hash()
}

pub fn generate_signed_quote_with_aik(
    nonce: [u8; 32],
    timestamp: u64,
    aik: &ed25519_dalek::SigningKey,
) -> AttestationQuote {
    let state = ATTESTATION_STATE.lock();
    state.generate_signed_quote(nonce, timestamp, aik)
}

pub fn verify_attestation_quote(quote: &AttestationQuote, attestation_public_key: &[u8; 32]) -> bool {
    quote.verify(attestation_public_key)
}
