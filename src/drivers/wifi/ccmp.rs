// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! CCMP (Counter Mode with CBC-MAC Protocol) implementation for WiFi
//!
//! IEEE 802.11i CCMP uses AES-128 in CCM mode for data encryption.
//! - 8-byte MIC (Message Integrity Code)
//! - 48-bit Packet Number (PN) for replay protection
//! - 16-byte AES-128 temporal key (TK)

extern crate alloc;

use alloc::vec::Vec;
use crate::crypto::symmetric::aes::Aes128;

pub(super) const CCMP_HEADER_SIZE: usize = 8;

pub(super) const CCMP_MIC_SIZE: usize = 8;

const _AES_BLOCK_SIZE: usize = 16;

pub(super) struct CcmpContext {
    aes: Aes128,
    tx_pn: u64,
    rx_pn: u64,
}

impl CcmpContext {
    pub(super) fn new(tk: &[u8; 16]) -> Self {
        Self {
            aes: Aes128::new(tk),
            tx_pn: 0,
            rx_pn: 0,
        }
    }

    pub(super) fn encrypt(&mut self, header: &[u8], data: &[u8], key_id: u8) -> Vec<u8> {
        self.tx_pn = self.tx_pn.wrapping_add(1);
        let pn = self.tx_pn;

        let ccmp_header = build_ccmp_header(pn, key_id);

        let a2 = if header.len() >= 16 { &header[10..16] } else { &[0u8; 6] };
        let nonce = build_nonce(0, a2, pn);

        let aad = build_aad(header);

        let (ciphertext, mic) = ccm_encrypt(&self.aes, &nonce, &aad, data);

        let mut result = Vec::with_capacity(CCMP_HEADER_SIZE + ciphertext.len() + CCMP_MIC_SIZE);
        result.extend_from_slice(&ccmp_header);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&mic);
        result
    }

    pub(super) fn decrypt(&mut self, header: &[u8], ccmp_data: &[u8]) -> Result<Vec<u8>, CcmpError> {
        if ccmp_data.len() < CCMP_HEADER_SIZE + CCMP_MIC_SIZE {
            return Err(CcmpError::InvalidLength);
        }

        let ccmp_header = &ccmp_data[..CCMP_HEADER_SIZE];
        let pn = extract_pn(ccmp_header);

        if pn <= self.rx_pn {
            return Err(CcmpError::ReplayDetected);
        }

        let ciphertext = &ccmp_data[CCMP_HEADER_SIZE..ccmp_data.len() - CCMP_MIC_SIZE];
        let mic = &ccmp_data[ccmp_data.len() - CCMP_MIC_SIZE..];

        let a2 = if header.len() >= 16 { &header[10..16] } else { &[0u8; 6] };
        let nonce = build_nonce(0, a2, pn);

        let aad = build_aad(header);

        let plaintext = ccm_decrypt(&self.aes, &nonce, &aad, ciphertext, mic)?;

        self.rx_pn = pn;

        Ok(plaintext)
    }

    pub(super) fn _tx_pn(&self) -> u64 {
        self.tx_pn
    }
}

fn build_ccmp_header(pn: u64, key_id: u8) -> [u8; 8] {
    [
        (pn & 0xFF) as u8,         // PN0
        ((pn >> 8) & 0xFF) as u8,  // PN1
        0,                          // Reserved
        (key_id << 6) | 0x20,      // KeyID | ExtIV bit set
        ((pn >> 16) & 0xFF) as u8, // PN2
        ((pn >> 24) & 0xFF) as u8, // PN3
        ((pn >> 32) & 0xFF) as u8, // PN4
        ((pn >> 40) & 0xFF) as u8, // PN5
    ]
}

fn extract_pn(header: &[u8]) -> u64 {
    (header[0] as u64)
        | ((header[1] as u64) << 8)
        | ((header[4] as u64) << 16)
        | ((header[5] as u64) << 24)
        | ((header[6] as u64) << 32)
        | ((header[7] as u64) << 40)
}

fn build_nonce(priority: u8, a2: &[u8], pn: u64) -> [u8; 13] {
    let mut nonce = [0u8; 13];
    nonce[0] = priority;
    nonce[1..7].copy_from_slice(&a2[..6.min(a2.len())]);
    nonce[7] = ((pn >> 40) & 0xFF) as u8;
    nonce[8] = ((pn >> 32) & 0xFF) as u8;
    nonce[9] = ((pn >> 24) & 0xFF) as u8;
    nonce[10] = ((pn >> 16) & 0xFF) as u8;
    nonce[11] = ((pn >> 8) & 0xFF) as u8;
    nonce[12] = (pn & 0xFF) as u8;
    nonce
}

fn build_aad(header: &[u8]) -> Vec<u8> {
    let header_len = header.len().min(24);
    let mut aad = Vec::with_capacity(header_len);

    if header_len >= 2 {
        let fc0 = header[0] & 0x8F; // Mask subtype bits
        let fc1 = header[1] & 0xC7; // Mask retry/pwrmgmt/moredata
        aad.push(fc0);
        aad.push(fc1);
    }

    if header_len >= 24 {
        aad.extend_from_slice(&header[4..24]); // Addr1, Addr2, Addr3
    }

    if header_len >= 24 {
        aad.push(header[22] & 0x0F);
        aad.push(0);
    }

    aad
}

fn ccm_encrypt(aes: &Aes128, nonce: &[u8; 13], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 8]) {
    let mut t = compute_cbc_mac(aes, nonce, aad, plaintext);

    let ciphertext = ctr_encrypt(aes, nonce, plaintext);

    let s0 = ctr_block(aes, nonce, 0);
    for i in 0..8 {
        t[i] ^= s0[i];
    }

    let mut mic = [0u8; 8];
    mic.copy_from_slice(&t[..8]);

    (ciphertext, mic)
}

fn ccm_decrypt(aes: &Aes128, nonce: &[u8; 13], aad: &[u8], ciphertext: &[u8], mic: &[u8]) -> Result<Vec<u8>, CcmpError> {
    let plaintext = ctr_encrypt(aes, nonce, ciphertext);

    let mut t = compute_cbc_mac(aes, nonce, aad, &plaintext);

    let s0 = ctr_block(aes, nonce, 0);
    for i in 0..8 {
        t[i] ^= s0[i];
    }

    let mut diff = 0u8;
    for i in 0..8 {
        diff |= t[i] ^ mic[i];
    }

    if diff != 0 {
        return Err(CcmpError::MicFailure);
    }

    Ok(plaintext)
}

fn compute_cbc_mac(aes: &Aes128, nonce: &[u8; 13], aad: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac: [u8; 16];

    let mut b0 = [0u8; 16];
    b0[0] = (3 << 3) | (if !aad.is_empty() { 0x40 } else { 0 }) | 1;
    b0[1..14].copy_from_slice(nonce);
    b0[14] = ((data.len() >> 8) & 0xFF) as u8;
    b0[15] = (data.len() & 0xFF) as u8;

    mac = aes.encrypt_block(&b0);

    if !aad.is_empty() {
        let mut block = [0u8; 16];
        let aad_len = aad.len();

        if aad_len < 0xFF00 {
            block[0] = ((aad_len >> 8) & 0xFF) as u8;
            block[1] = (aad_len & 0xFF) as u8;
            let copy_len = 14.min(aad_len);
            block[2..2 + copy_len].copy_from_slice(&aad[..copy_len]);

            for i in 0..16 {
                mac[i] ^= block[i];
            }
            mac = aes.encrypt_block(&mac);

            let mut offset = copy_len;
            while offset < aad_len {
                block = [0u8; 16];
                let copy_len = 16.min(aad_len - offset);
                block[..copy_len].copy_from_slice(&aad[offset..offset + copy_len]);

                for i in 0..16 {
                    mac[i] ^= block[i];
                }
                mac = aes.encrypt_block(&mac);
                offset += 16;
            }
        }
    }

    let mut offset = 0;
    while offset < data.len() {
        let mut block = [0u8; 16];
        let copy_len = 16.min(data.len() - offset);
        block[..copy_len].copy_from_slice(&data[offset..offset + copy_len]);

        for i in 0..16 {
            mac[i] ^= block[i];
        }
        mac = aes.encrypt_block(&mac);
        offset += 16;
    }

    mac
}

fn ctr_encrypt(aes: &Aes128, nonce: &[u8; 13], data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut counter = 1u16; // Start at 1 (0 is reserved for tag encryption)
    let mut offset = 0;

    while offset < data.len() {
        let keystream = ctr_block(aes, nonce, counter);
        let block_len = 16.min(data.len() - offset);

        for i in 0..block_len {
            result.push(data[offset + i] ^ keystream[i]);
        }

        offset += 16;
        counter = counter.wrapping_add(1);
    }

    result
}

fn ctr_block(aes: &Aes128, nonce: &[u8; 13], counter: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 1;
    a[1..14].copy_from_slice(nonce);
    a[14] = ((counter >> 8) & 0xFF) as u8;
    a[15] = (counter & 0xFF) as u8;
    aes.encrypt_block(&a)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CcmpError {
    InvalidLength,
    MicFailure,
    ReplayDetected,
}
