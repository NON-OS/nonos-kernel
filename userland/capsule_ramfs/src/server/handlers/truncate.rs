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

use alloc::string::String;
use alloc::vec::Vec;

use crate::handles::HandleTable;
use crate::protocol::{encode_response, Request, EINVAL, EIO, ENOENT};
use crate::store::{Store, StoreError};

pub fn truncate(store: &mut Store, handles: &HandleTable, req: Request<'_>) -> Vec<u8> {
    if req.payload.len() < 16 {
        return encode_response(req.seq, EINVAL, &[]);
    }
    let h = u64::from_le_bytes(req.payload[0..8].try_into().unwrap());
    let length = u64::from_le_bytes(req.payload[8..16].try_into().unwrap()) as usize;
    let path = match handles.path_of(h) {
        Some(p) => String::from(p),
        None => return encode_response(req.seq, ENOENT, &[]),
    };
    match store.truncate(&path, length) {
        Ok(()) => encode_response(req.seq, 0, &[]),
        Err(StoreError::NotFound) => encode_response(req.seq, ENOENT, &[]),
        Err(StoreError::CryptoFailure) => encode_response(req.seq, EIO, &[]),
    }
}
