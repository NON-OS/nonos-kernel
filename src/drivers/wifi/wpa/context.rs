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

use alloc::vec::Vec;
use super::super::error::WifiError;
use super::super::scan::SecurityType;
use super::constants::*;
use super::handshake::HandshakeState;
use super::crypto::*;
use super::sae::{SaeContext, SaeCommit, sae_derive_pwd_seed};

pub struct WpaContext {
    pub security: SecurityType,
    pub state: HandshakeState,
    pub pmk: [u8; PMK_LEN],
    pub ptk: [u8; PTK_LEN],
    pub anonce: [u8; NONCE_LEN],
    pub snonce: [u8; NONCE_LEN],
    pub aa: [u8; 6],
    pub spa: [u8; 6],
    pub replay_counter: u64,
    pub key_confirmed: bool,
}

impl WpaContext {
    pub fn new(security: SecurityType, client_mac: [u8; 6], ap_mac: [u8; 6]) -> Self {
        Self {
            security,
            state: HandshakeState::Idle,
            pmk: [0u8; PMK_LEN],
            ptk: [0u8; PTK_LEN],
            anonce: [0u8; NONCE_LEN],
            snonce: [0u8; NONCE_LEN],
            aa: ap_mac,
            spa: client_mac,
            replay_counter: 0,
            key_confirmed: false,
        }
    }

    pub fn derive_pmk(&mut self, password: &str, ssid: &str) -> Result<(), WifiError> {
        match self.security {
            SecurityType::Wpa2Psk | SecurityType::WpaPsk => {
                pbkdf2_sha1(
                    password.as_bytes(),
                    ssid.as_bytes(),
                    4096,
                    &mut self.pmk,
                )?;
                Ok(())
            }
            SecurityType::Wpa3Sae => {
                self.derive_pmk_sae(password, ssid)
            }
            SecurityType::Open => {
                Ok(())
            }
            SecurityType::Wep | SecurityType::Enterprise | SecurityType::Unknown => {
                Err(WifiError::UnsupportedSecurity)
            }
        }
    }

    fn derive_pmk_sae(&mut self, password: &str, _ssid: &str) -> Result<(), WifiError> {
        let pwd_seed = sae_derive_pwd_seed(password.as_bytes(), &self.aa, &self.spa);
        self.pmk.copy_from_slice(&pwd_seed);
        Ok(())
    }

    pub fn init_sae(&mut self, password: &str) -> Result<SaeContext, WifiError> {
        let sae = SaeContext::new(password, &self.aa, &self.spa)?;
        Ok(sae)
    }

    pub fn process_sae_commit(&mut self, sae: &mut SaeContext, peer_commit: &SaeCommit) -> Result<SaeCommit, WifiError> {
        sae.set_peer_commit(peer_commit)?;

        if sae.our_commit.is_none() {
            sae.generate_commit()?;
        }

        Ok(sae.our_commit.clone().ok_or(WifiError::InvalidState)?)
    }

    pub fn process_sae_confirm(&mut self, sae: &mut SaeContext, peer_confirm: &[u8]) -> Result<Vec<u8>, WifiError> {
        sae.verify_peer_confirm(peer_confirm)?;

        let our_confirm = sae.generate_confirm()?;

        let pmk = sae.derive_pmk()?;
        self.pmk.copy_from_slice(&pmk);

        self.state = HandshakeState::Complete;
        self.key_confirmed = true;

        Ok(our_confirm)
    }

    pub fn generate_snonce(&mut self) -> Result<(), WifiError> {
        crate::crypto::fill_random_bytes(&mut self.snonce);
        Ok(())
    }

    pub fn process_msg1(&mut self, anonce: &[u8], replay_counter: u64) -> Result<Vec<u8>, WifiError> {
        if self.state != HandshakeState::Idle {
            return Err(WifiError::InvalidState);
        }

        if anonce.len() != NONCE_LEN {
            return Err(WifiError::InvalidFrame);
        }
        self.anonce.copy_from_slice(anonce);
        self.replay_counter = replay_counter;

        self.generate_snonce()?;
        self.derive_ptk()?;

        let msg2 = self.build_eapol_msg2()?;

        self.state = HandshakeState::WaitingMsg3;
        Ok(msg2)
    }

    pub fn process_msg3(&mut self, frame: &[u8], key_data: &[u8], mic: &[u8], replay_counter: u64) -> Result<Vec<u8>, WifiError> {
        if self.state != HandshakeState::WaitingMsg3 {
            return Err(WifiError::InvalidState);
        }

        if replay_counter <= self.replay_counter {
            return Err(WifiError::ReplayAttack);
        }
        self.replay_counter = replay_counter;

        let kck = &self.ptk[0..KCK_LEN];
        if !self.verify_mic(kck, frame, mic)? {
            return Err(WifiError::MicFailure);
        }

        let kek = &self.ptk[KCK_LEN..KCK_LEN + KEK_LEN];
        let _gtk = self.decrypt_key_data(kek, key_data)?;

        let msg4 = self.build_eapol_msg4()?;

        self.state = HandshakeState::Complete;
        self.key_confirmed = true;

        Ok(msg4)
    }

    fn derive_ptk(&mut self) -> Result<(), WifiError> {
        let mut data = Vec::with_capacity(76);

        if self.aa < self.spa {
            data.extend_from_slice(&self.aa);
            data.extend_from_slice(&self.spa);
        } else {
            data.extend_from_slice(&self.spa);
            data.extend_from_slice(&self.aa);
        }

        if self.anonce < self.snonce {
            data.extend_from_slice(&self.anonce);
            data.extend_from_slice(&self.snonce);
        } else {
            data.extend_from_slice(&self.snonce);
            data.extend_from_slice(&self.anonce);
        }

        prf_sha1(&self.pmk, b"Pairwise key expansion", &data, &mut self.ptk)?;

        Ok(())
    }

    fn build_eapol_msg2(&self) -> Result<Vec<u8>, WifiError> {
        let mut frame = Vec::with_capacity(99);

        frame.push(0x02);
        frame.push(0x03);
        let body_len: u16 = 95;
        frame.extend_from_slice(&body_len.to_be_bytes());

        frame.push(EAPOL_KEY_TYPE_RSN);

        let key_info: u16 = 0x010A;
        frame.extend_from_slice(&key_info.to_be_bytes());

        let key_len: u16 = 16;
        frame.extend_from_slice(&key_len.to_be_bytes());

        frame.extend_from_slice(&self.replay_counter.to_be_bytes());

        frame.extend_from_slice(&self.snonce);

        frame.extend_from_slice(&[0u8; 16]);

        frame.extend_from_slice(&[0u8; 8]);

        frame.extend_from_slice(&[0u8; 8]);

        let mic_offset = frame.len();
        frame.extend_from_slice(&[0u8; MIC_LEN]);

        let key_data_len: u16 = 22;
        frame.extend_from_slice(&key_data_len.to_be_bytes());

        frame.extend_from_slice(&[
            0x30, 0x14,
            0x01, 0x00,
            0x00, 0x0f, 0xac, 0x04,
            0x01, 0x00,
            0x00, 0x0f, 0xac, 0x04,
            0x01, 0x00,
            0x00, 0x0f, 0xac, 0x02,
            0x00, 0x00,
        ]);

        let kck = &self.ptk[0..KCK_LEN];
        let mic = compute_mic_aes_cmac(kck, &frame[4..])?;
        frame[mic_offset..mic_offset + MIC_LEN].copy_from_slice(&mic);

        Ok(frame)
    }

    fn build_eapol_msg4(&self) -> Result<Vec<u8>, WifiError> {
        let mut frame = Vec::with_capacity(99);

        frame.push(0x02);
        frame.push(0x03);
        let body_len: u16 = 95;
        frame.extend_from_slice(&body_len.to_be_bytes());

        frame.push(EAPOL_KEY_TYPE_RSN);

        let key_info: u16 = 0x030A;
        frame.extend_from_slice(&key_info.to_be_bytes());

        frame.extend_from_slice(&16u16.to_be_bytes());

        frame.extend_from_slice(&self.replay_counter.to_be_bytes());

        frame.extend_from_slice(&[0u8; NONCE_LEN]);

        frame.extend_from_slice(&[0u8; 16 + 8 + 8]);

        let mic_offset = frame.len();
        frame.extend_from_slice(&[0u8; MIC_LEN]);

        frame.extend_from_slice(&0u16.to_be_bytes());

        let kck = &self.ptk[0..KCK_LEN];
        let mic = compute_mic_aes_cmac(kck, &frame[4..])?;
        frame[mic_offset..mic_offset + MIC_LEN].copy_from_slice(&mic);

        Ok(frame)
    }

    fn verify_mic(&self, kck: &[u8], frame_data: &[u8], received_mic: &[u8]) -> Result<bool, WifiError> {
        if received_mic.len() != MIC_LEN {
            return Ok(false);
        }
        if frame_data.len() < 99 {
            return Ok(false);
        }

        let mut frame_copy = Vec::from(frame_data);

        const MIC_OFFSET: usize = 81;
        for i in 0..MIC_LEN {
            if MIC_OFFSET + i < frame_copy.len() {
                frame_copy[MIC_OFFSET + i] = 0;
            }
        }

        let computed_mic = compute_mic_aes_cmac(kck, &frame_copy[4..])?;

        let mut diff = 0u8;
        for i in 0..MIC_LEN {
            diff |= computed_mic[i] ^ received_mic[i];
        }

        Ok(diff == 0)
    }

    fn decrypt_key_data(&self, kek: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, WifiError> {
        if encrypted.len() < 24 || encrypted.len() % 8 != 0 {
            return Err(WifiError::InvalidFrame);
        }

        aes_key_unwrap(kek, encrypted)
    }

    pub fn get_temporal_key(&self) -> Option<&[u8]> {
        if self.key_confirmed {
            Some(&self.ptk[KCK_LEN + KEK_LEN..KCK_LEN + KEK_LEN + TK_LEN])
        } else {
            None
        }
    }

    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Complete && self.key_confirmed
    }
}
