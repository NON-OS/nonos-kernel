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

mod decode;
mod encode;
mod types;

pub(super) use decode::{decode_response, Response};
pub(super) use encode::{
    encode_count, encode_delete, encode_lock, encode_metadata, encode_retrieve, encode_store,
    encode_unlock,
};
pub(super) use types::{
    ERRNO_ACCESS, ERRNO_BUSY, ERRNO_INVAL, ERRNO_NOSPC, ERRNO_NOT_FOUND, KERNEL_REPLY_ENDPOINT,
};
