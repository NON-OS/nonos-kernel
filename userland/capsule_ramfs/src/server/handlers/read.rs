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

use crate::handles::HandleTable;
use crate::protocol::{encode_response, Request, EINVAL, EIO, ENOENT};
use crate::store::{Store, StoreError};

pub fn read(store: &Store, handles: &HandleTable, req: Request<'_>) -> Vec<u8> {
    if req.payload.len() < 20 {
        return encode_response(req.seq, EINVAL, &[]);
    }
    let h = u64::from_le_bytes(req.payload[0..8].try_into().unwrap());
    let offset = u64::from_le_bytes(req.payload[8..16].try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(req.payload[16..20].try_into().unwrap()) as usize;
    let path = match handles.path_of(h) {
        Some(p) => p,
        None => return encode_response(req.seq, ENOENT, &[]),
    };
    match store.read_at(path, offset, count) {
        Ok(bytes) => encode_response(req.seq, bytes.len() as i32, &bytes),
        Err(StoreError::NotFound) => encode_response(req.seq, ENOENT, &[]),
        Err(StoreError::CryptoFailure) => encode_response(req.seq, EIO, &[]),
    }
}
