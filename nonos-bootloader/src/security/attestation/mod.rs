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

mod api;
mod pcr;
mod quote;
mod state;

pub use api::{
    extend_pcr, extend_pcr_hash, generate_attestation_quote, generate_signed_quote_with_aik,
    get_boot_measurement, init_attestation, set_bootloader_measurement, set_kernel_measurement,
    set_signature_attestation, set_zk_attestation, verify_attestation_quote, ATTESTATION_STATE,
};
pub use pcr::{PcrIndex, PcrValue, DS_ATTESTATION, MAX_PCRS};
pub use quote::AttestationQuote;
pub use state::AttestationState;
