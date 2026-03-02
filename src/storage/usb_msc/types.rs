// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.


use super::constants::{CBW_SIGNATURE, CBW_FLAG_DATA_IN, CBW_SIZE};

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CommandBlockWrapper {
    pub signature: u32,
    pub tag: u32,
    pub data_transfer_length: u32,
    pub flags: u8,
    pub lun: u8,
    pub cb_length: u8,
    pub cb: [u8; 16],
}

impl CommandBlockWrapper {
    pub fn new(tag: u32, data_len: u32, direction_in: bool, lun: u8, command: &[u8]) -> Self {
        let mut cbw = Self {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_length: data_len,
            flags: if direction_in { CBW_FLAG_DATA_IN } else { 0x00 },
            lun,
            cb_length: command.len().min(16) as u8,
            cb: [0u8; 16],
        };

        let len = command.len().min(16);
        cbw.cb[..len].copy_from_slice(&command[..len]);
        cbw
    }

    pub fn as_bytes(&self) -> [u8; CBW_SIZE] {
        let mut bytes = [0u8; CBW_SIZE];
        bytes[0..4].copy_from_slice(&self.signature.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.tag.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.data_transfer_length.to_le_bytes());
        bytes[12] = self.flags;
        bytes[13] = self.lun;
        bytes[14] = self.cb_length;
        bytes[15..31].copy_from_slice(&self.cb);
        bytes
    }
}

#[derive(Clone, Copy)]
pub struct MscDevice {
    pub present: bool,
    pub bulk_in_ep: u8,
    pub bulk_out_ep: u8,
    pub block_size: u32,
    pub total_blocks: u64,
}

impl MscDevice {
    pub const fn empty() -> Self {
        Self {
            present: false,
            bulk_in_ep: 0,
            bulk_out_ep: 0,
            block_size: 512,
            total_blocks: 0,
        }
    }
}
