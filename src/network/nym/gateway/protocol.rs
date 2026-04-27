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

use super::connection::GatewayConnection;
use crate::network::nym::error::NymError;
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub enum GatewayMessage {
    SphinxPacket(Vec<u8>),
    Ack(u64),
    Ping,
    Pong,
    Error(u8),
}

const MSG_SPHINX: u8 = 0x01;
const MSG_ACK: u8 = 0x02;
const MSG_PING: u8 = 0x03;
const MSG_PONG: u8 = 0x04;
const MSG_ERROR: u8 = 0xFF;

pub fn send_message(conn: &GatewayConnection, msg: &GatewayMessage) -> Result<(), NymError> {
    let data = encode_message(msg)?;
    let encrypted = encrypt_frame(&conn.shared_key, &data)?;
    let mut frame = Vec::with_capacity(4 + encrypted.len());
    frame.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
    frame.extend_from_slice(&encrypted);
    conn.send(&frame)
}

pub fn recv_message(conn: &GatewayConnection) -> Result<GatewayMessage, NymError> {
    let mut len_buf = [0u8; 4];
    conn.recv(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 65536 {
        return Err(NymError::InvalidPacket);
    }
    let mut encrypted = vec![0u8; len];
    conn.recv(&mut encrypted)?;
    let data = decrypt_frame(&conn.shared_key, &encrypted)?;
    decode_message(&data)
}

fn encode_message(msg: &GatewayMessage) -> Result<Vec<u8>, NymError> {
    let mut out = Vec::new();
    match msg {
        GatewayMessage::SphinxPacket(data) => {
            out.push(MSG_SPHINX);
            out.extend_from_slice(data);
        }
        GatewayMessage::Ack(seq) => {
            out.push(MSG_ACK);
            out.extend_from_slice(&seq.to_be_bytes());
        }
        GatewayMessage::Ping => out.push(MSG_PING),
        GatewayMessage::Pong => out.push(MSG_PONG),
        GatewayMessage::Error(code) => {
            out.push(MSG_ERROR);
            out.push(*code);
        }
    }
    Ok(out)
}

fn decode_message(data: &[u8]) -> Result<GatewayMessage, NymError> {
    if data.is_empty() {
        return Err(NymError::InvalidPacket);
    }
    match data[0] {
        MSG_SPHINX => Ok(GatewayMessage::SphinxPacket(data[1..].to_vec())),
        MSG_ACK if data.len() >= 9 => {
            let mut seq_bytes = [0u8; 8];
            seq_bytes.copy_from_slice(&data[1..9]);
            Ok(GatewayMessage::Ack(u64::from_be_bytes(seq_bytes)))
        }
        MSG_PING => Ok(GatewayMessage::Ping),
        MSG_PONG => Ok(GatewayMessage::Pong),
        MSG_ERROR if data.len() >= 2 => Ok(GatewayMessage::Error(data[1])),
        _ => Err(NymError::InvalidPacket),
    }
}

fn encrypt_frame(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, NymError> {
    let nonce = generate_nonce();
    let ct = crate::network::nym::crypto::aes_gcm_encrypt(key, &nonce, data, &[])
        .ok_or(NymError::EncryptionFailed)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_frame(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, NymError> {
    if data.len() < 12 {
        return Err(NymError::InvalidPacket);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[..12]);
    crate::network::nym::crypto::aes_gcm_decrypt(key, &nonce, &data[12..], &[])
        .ok_or(NymError::DecryptionFailed)
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let _ = crate::crypto::random::fill_bytes(&mut nonce);
    nonce
}
