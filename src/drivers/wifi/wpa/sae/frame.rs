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
use super::super::super::error::WifiError;
use super::types::SaeCommit;

pub struct SaeFrame {
    pub transaction: u16,
    pub status: u16,
    pub payload: Vec<u8>,
}

impl SaeFrame {
    pub fn is_commit(&self) -> bool {
        self.transaction == 1
    }

    pub fn is_confirm(&self) -> bool {
        self.transaction == 2
    }

    pub fn build_commit(commit: &SaeCommit) -> Vec<u8> {
        let mut frame = Vec::with_capacity(6 + 65);
        frame.extend_from_slice(&3u16.to_le_bytes());
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&commit.to_bytes());
        frame
    }

    pub fn build_confirm(confirm: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(6 + confirm.len());
        frame.extend_from_slice(&3u16.to_le_bytes());
        frame.extend_from_slice(&2u16.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(confirm);
        frame
    }
}

pub fn parse_sae_frame(frame: &[u8]) -> Result<SaeFrame, WifiError> {
    if frame.len() < 4 {
        return Err(WifiError::InvalidFrame);
    }

    let algo = u16::from_le_bytes([frame[0], frame[1]]);
    let trans_seq = u16::from_le_bytes([frame[2], frame[3]]);

    if algo != 3 {
        return Err(WifiError::InvalidFrame);
    }

    let status = if frame.len() >= 6 {
        u16::from_le_bytes([frame[4], frame[5]])
    } else {
        0
    };

    let payload = if frame.len() > 6 {
        frame[6..].to_vec()
    } else {
        Vec::new()
    };

    Ok(SaeFrame {
        transaction: trans_seq,
        status,
        payload,
    })
}
