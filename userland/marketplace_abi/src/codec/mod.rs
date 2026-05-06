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

mod decode_entry;
mod decode_index;
mod decode_price;
mod decode_release;
mod decode_token;
mod decode_validation;
#[cfg(feature = "canonical-encode")]
mod encode_entry;
#[cfg(feature = "canonical-encode")]
mod encode_index;
#[cfg(feature = "canonical-encode")]
mod encode_price;
#[cfg(feature = "canonical-encode")]
mod encode_release;
#[cfg(feature = "canonical-encode")]
mod encode_token;
#[cfg(feature = "canonical-encode")]
mod encode_validation;
mod error;
mod reader;
mod strings;
#[cfg(feature = "canonical-encode")]
mod writer;

pub use decode_index::{decode_index, DecodedIndex};
#[cfg(feature = "canonical-encode")]
pub use encode_index::{encode_and_sign, encode_index, EncodedIndex};
pub use error::DecodeError;
