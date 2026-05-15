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

mod codec;
mod header;
mod ops;

pub(super) use codec::{decode_response, encode_request};
pub(super) use header::{
    CODEC_ENTRY_BYTES, CODEC_LIST_HEADER_BYTES, CODEC_MASK_PAYLOAD_LEN,
    CONTROLLER_INFO_PAYLOAD_LEN, MAX_CODECS, MAX_STREAMS, STREAM_ENTRY_BYTES,
    STREAM_LAYOUT_HEADER_BYTES,
};
pub(super) use ops::{
    OP_CODEC_LIST, OP_CODEC_MASK, OP_CONTROLLER_INFO, OP_HEALTHCHECK, OP_STREAM_LAYOUT,
};
