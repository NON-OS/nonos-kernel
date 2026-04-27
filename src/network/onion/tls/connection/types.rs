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

use super::super::aead::AeadState;
use super::super::keys::{KeySchedule, Secret};
use super::super::session::SessionCache;
use super::super::transcript::Transcript;
use super::super::types::CipherSuite;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    Idle,
    SentClientHello,
    ReceivedServerHello,
    ReceivedEncrypted,
    SentFinished,
    Complete,
    Failed,
}

pub struct TLSConnection {
    pub(super) suite: CipherSuite,
    pub(super) transcript: Transcript,
    pub(super) ks: KeySchedule,
    pub(super) rx_hs: AeadState,
    pub(super) tx_hs: AeadState,
    pub(super) rx_app: Option<AeadState>,
    pub(super) tx_app: Option<AeadState>,
    pub(super) phase: HandshakePhase,
    pub(super) client_random: [u8; 32],
    pub(super) ephemeral_x25519: [u8; 32],
    pub(super) ephemeral_p256: [u8; 32],
    pub(super) server_random: [u8; 32],
    pub(super) server_pub: Vec<u8>,
    pub(super) server_group: u16,
    pub(super) server_certs: Vec<Vec<u8>>,
    pub(super) cert_verify_alg: Option<u16>,
    pub(super) cert_verify_sig: Vec<u8>,
    pub(super) cert_verify_hash: [u8; 48],
    pub(super) got_finished: bool,
    pub(super) recv_buffer: Vec<u8>,
    pub(super) hs_reassembly: Vec<u8>,
    // HRR support fields
    pub(super) hrr_count: u8,
    pub(super) sni_cache: Option<String>,
    pub(super) alpn_cache: Option<Vec<String>>,
    // Session resumption fields
    pub(super) resumption_secret: Option<Secret>,
    pub(super) session_cache: Option<&'static SessionCache>,
    pub(super) using_psk: bool,
    pub(super) psk_suite: Option<CipherSuite>,
    pub(super) psk_value: Option<Vec<u8>>,
}

impl Drop for TLSConnection {
    fn drop(&mut self) {
        for byte in self.ephemeral_x25519.iter_mut() {
            // SAFETY: volatile write prevents compiler from optimizing away the zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.ephemeral_p256.iter_mut() {
            // SAFETY: volatile write prevents compiler from optimizing away the zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.client_random.iter_mut() {
            // SAFETY: volatile write prevents compiler from optimizing away the zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.cert_verify_hash.iter_mut() {
            // SAFETY: volatile write prevents compiler from optimizing away the zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        // resumption_secret is zeroized by Secret's own Drop
        // psk_value is zeroized here
        if let Some(ref mut psk) = self.psk_value {
            for byte in psk.iter_mut() {
                // SAFETY: volatile write prevents compiler from eliding zeroization
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
