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

use super::{algorithm, output};
use crate::capabilities::Capability;
use crate::syscall::dispatch::crypto::error::{map_capsule_error, CryptoErrorContext};
use crate::syscall::dispatch::{errno, require_capability};
use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;

pub fn handle_crypto_hash(algo: u64, data: u64, len: u64, out: u64, out_len: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }
    if data == 0 || len == 0 || len > 1024 * 1024 {
        return errno(22);
    }
    let mut input = alloc::vec![0u8; len as usize];
    if copy_from_user(data, &mut input).is_err() {
        return errno(14);
    }
    match algorithm::digest(algo, &input) {
        Ok(digest) => output::write_or_truncate(&digest, out, out_len),
        Err(e) => map_capsule_error(e, CryptoErrorContext::Digest),
    }
}
