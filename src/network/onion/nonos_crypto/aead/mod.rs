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

mod aes128;
mod chacha;
mod tls;

pub use aes128::{aes128_gcm_open, aes128_gcm_seal};
pub use chacha::{chacha20poly1305_open, chacha20poly1305_seal};
pub use tls::{
    tls_aes128_gcm_open, tls_aes128_gcm_seal, tls_chacha20poly1305_open, tls_chacha20poly1305_seal,
};
pub use tls::{tls_aes256_gcm_open, tls_aes256_gcm_seal};
