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
use crate::crypto::asymmetric::p256::{Scalar, ProjectivePoint};
use super::super::super::error::WifiError;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SaeState {
    Nothing,
    Committed,
    Confirmed,
    Accepted,
}

#[derive(Clone)]
pub struct SaeCommit {
    pub scalar: [u8; 32],
    pub element: [u8; 33],
}

impl SaeCommit {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&self.scalar);
        bytes.extend_from_slice(&self.element);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WifiError> {
        if bytes.len() < 65 {
            return Err(WifiError::InvalidFrame);
        }
        let mut scalar = [0u8; 32];
        let mut element = [0u8; 33];
        scalar.copy_from_slice(&bytes[0..32]);
        element.copy_from_slice(&bytes[32..65]);
        Ok(Self { scalar, element })
    }
}

pub struct SaeContext {
    pub state: SaeState,
    pub(crate) pwe: ProjectivePoint,
    pub(crate) rand: Scalar,
    pub(crate) _mask: Scalar,
    pub(crate) commit_scalar: Scalar,
    pub(crate) commit_element: ProjectivePoint,
    pub(crate) peer_scalar: Option<Scalar>,
    pub(crate) peer_element: Option<ProjectivePoint>,
    pub(crate) shared_secret: Option<ProjectivePoint>,
    pub(crate) kck: [u8; 32],
    pub(crate) pmk: [u8; 32],
    pub(crate) spa: [u8; 6],
    pub(crate) aa: [u8; 6],
    pub our_commit: Option<SaeCommit>,
    pub(crate) send_confirm: u16,
}
