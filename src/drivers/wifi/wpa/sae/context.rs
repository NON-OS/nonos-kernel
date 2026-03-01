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
use crate::crypto::asymmetric::p256::{Scalar, AffinePoint};
use super::super::super::error::WifiError;
use super::super::crypto::{hmac_sha256, hkdf_expand_sha256};
use super::types::{SaeState, SaeCommit, SaeContext};
use super::dragonfly::{sae_derive_pwe, sae_generate_random_scalar};

impl SaeContext {
    pub fn new(password: &str, aa: &[u8; 6], spa: &[u8; 6]) -> Result<Self, WifiError> {
        let pwe = sae_derive_pwe(password.as_bytes(), aa, spa)?;

        let rand = sae_generate_random_scalar()?;

        let mask = sae_generate_random_scalar()?;

        let commit_scalar = rand.add(&mask);

        let mask_neg = mask.negate();
        let commit_element = pwe.mul(&mask_neg);

        Ok(Self {
            state: SaeState::Nothing,
            pwe,
            rand,
            _mask: mask,
            commit_scalar,
            commit_element,
            peer_scalar: None,
            peer_element: None,
            shared_secret: None,
            kck: [0u8; 32],
            pmk: [0u8; 32],
            spa: *spa,
            aa: *aa,
            our_commit: None,
            send_confirm: 0,
        })
    }

    pub fn generate_commit(&mut self) -> Result<(), WifiError> {
        let scalar_bytes = self.commit_scalar.to_bytes();
        let element_affine = self.commit_element.to_affine();
        let element_bytes = element_affine.to_compressed();

        self.our_commit = Some(SaeCommit {
            scalar: scalar_bytes,
            element: element_bytes,
        });

        self.state = SaeState::Committed;
        Ok(())
    }

    pub fn set_peer_commit(&mut self, commit: &SaeCommit) -> Result<(), WifiError> {
        let peer_scalar = Scalar::from_bytes(&commit.scalar)
            .ok_or(WifiError::InvalidFrame)?;

        if peer_scalar.is_zero() {
            return Err(WifiError::InvalidFrame);
        }

        let peer_element = AffinePoint::from_compressed(&commit.element)
            .ok_or(WifiError::InvalidFrame)?
            .to_projective();

        if peer_element.is_identity() {
            return Err(WifiError::InvalidFrame);
        }

        self.peer_scalar = Some(peer_scalar);
        self.peer_element = Some(peer_element);

        self.compute_shared_secret()?;

        Ok(())
    }

    fn compute_shared_secret(&mut self) -> Result<(), WifiError> {
        let peer_scalar = self.peer_scalar.as_ref().ok_or(WifiError::InvalidState)?;
        let peer_element = self.peer_element.as_ref().ok_or(WifiError::InvalidState)?;

        let scalar_pwe = self.pwe.mul(peer_scalar);
        let sum = scalar_pwe.add(peer_element);
        let k = sum.mul(&self.rand);

        if k.is_identity() {
            return Err(WifiError::AuthenticationFailed);
        }

        self.shared_secret = Some(k);

        self.derive_keys()?;

        Ok(())
    }

    fn derive_keys(&mut self) -> Result<(), WifiError> {
        let k = self.shared_secret.as_ref().ok_or(WifiError::InvalidState)?;
        let k_affine = k.to_affine();
        let k_x = k_affine.x.to_bytes();

        let peer_scalar = self.peer_scalar.as_ref().ok_or(WifiError::InvalidState)?;
        let mut key_seed = Vec::with_capacity(96);
        key_seed.extend_from_slice(&k_x);

        if self.spa < self.aa {
            key_seed.extend_from_slice(&self.commit_scalar.to_bytes());
            key_seed.extend_from_slice(&peer_scalar.to_bytes());
        } else {
            key_seed.extend_from_slice(&peer_scalar.to_bytes());
            key_seed.extend_from_slice(&self.commit_scalar.to_bytes());
        }

        let prk = hmac_sha256(b"SAE Keyseed", &key_seed);

        self.kck = hkdf_expand_sha256(&prk, b"SAE KCK", 32);

        self.pmk = hkdf_expand_sha256(&prk, b"SAE PMK", 32);

        Ok(())
    }

    pub fn generate_confirm(&mut self) -> Result<Vec<u8>, WifiError> {
        if self.state != SaeState::Committed {
            return Err(WifiError::InvalidState);
        }

        self.send_confirm += 1;

        let confirm = self.compute_confirm(
            self.send_confirm,
            &self.commit_scalar,
            self.peer_scalar.as_ref().ok_or(WifiError::InvalidState)?,
            &self.commit_element,
            self.peer_element.as_ref().ok_or(WifiError::InvalidState)?,
        )?;

        self.state = SaeState::Confirmed;

        let mut msg = Vec::with_capacity(2 + 32);
        msg.extend_from_slice(&self.send_confirm.to_le_bytes());
        msg.extend_from_slice(&confirm);
        Ok(msg)
    }

    pub fn verify_peer_confirm(&mut self, confirm_msg: &[u8]) -> Result<(), WifiError> {
        if confirm_msg.len() < 34 {
            return Err(WifiError::InvalidFrame);
        }

        let peer_send_confirm = u16::from_le_bytes([confirm_msg[0], confirm_msg[1]]);
        let peer_confirm = &confirm_msg[2..34];

        let expected = self.compute_confirm(
            peer_send_confirm,
            self.peer_scalar.as_ref().ok_or(WifiError::InvalidState)?,
            &self.commit_scalar,
            self.peer_element.as_ref().ok_or(WifiError::InvalidState)?,
            &self.commit_element,
        )?;

        let mut diff = 0u8;
        for i in 0..32 {
            diff |= peer_confirm[i] ^ expected[i];
        }

        if diff != 0 {
            return Err(WifiError::AuthenticationFailed);
        }

        self.state = SaeState::Accepted;
        Ok(())
    }

    fn compute_confirm(
        &self,
        send_confirm: u16,
        scalar1: &Scalar,
        scalar2: &Scalar,
        element1: &crate::crypto::asymmetric::p256::ProjectivePoint,
        element2: &crate::crypto::asymmetric::p256::ProjectivePoint,
    ) -> Result<[u8; 32], WifiError> {
        let mut input = Vec::with_capacity(200);
        input.extend_from_slice(&self.kck);
        input.extend_from_slice(&send_confirm.to_le_bytes());
        input.extend_from_slice(&scalar1.to_bytes());
        input.extend_from_slice(&scalar2.to_bytes());
        input.extend_from_slice(&element1.to_affine().to_compressed());
        input.extend_from_slice(&element2.to_affine().to_compressed());

        if self.spa < self.aa {
            input.extend_from_slice(&self.spa);
            input.extend_from_slice(&self.aa);
        } else {
            input.extend_from_slice(&self.aa);
            input.extend_from_slice(&self.spa);
        }

        Ok(hmac_sha256(b"SAE Confirm", &input))
    }

    pub fn derive_pmk(&self) -> Result<[u8; 32], WifiError> {
        if self.state != SaeState::Accepted {
            return Err(WifiError::InvalidState);
        }
        Ok(self.pmk)
    }
}
