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

pub mod core;
pub mod crypto;
pub mod hardware;
pub mod security;
pub mod storage;
pub mod types;

pub use core::{TmpDevice, TmpError, TmpResult, initialize_tpm};
pub use crypto::{extend_pcr, read_pcr, get_random, compute_hash};
pub use hardware::{acquire_locality, release_locality, send_command};
pub use security::{create_attestation, verify_quote, create_session};
pub use storage::{nv_read, nv_write, create_key, load_key};
pub use types::{NvIndex, PcrBank, Quote, TmpHandle, Session};