// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::log_ok;
use crate::log::logger::log_info;
use crate::security::{generate_attestation_quote, AttestationQuote};

pub fn generate_boot_attestation(rng_seed: &[u8; 32], gop: bool) -> AttestationQuote {
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(rng_seed);
    let timestamp = unsafe { core::arch::x86_64::_rdtsc() } as u64;
    let quote = generate_attestation_quote(nonce, timestamp);
    log_info("attestation", "boot attestation quote generated");
    if gop {
        log_ok(b"TPM attestation quote generated");
    }
    quote
}
