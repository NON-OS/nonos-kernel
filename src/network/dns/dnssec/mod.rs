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

mod error;
mod keys;
mod rrsig;
mod trust_anchor;
mod types;
mod validate;

pub use error::{DnssecError, DnssecResult};
pub use keys::{compute_ds_digest, compute_key_tag, parse_dnskey};
pub use rrsig::{build_rrset_data, parse_rrsig, verify_rrsig};
pub use trust_anchor::{get_root_trust_anchors, is_trusted_key, verify_ds_chain};
pub use types::{
    DnskeyRecord, DnssecAlgorithm, DsRecord, NsecRecord, RrsigRecord, DNSKEY_TYPE, DS_TYPE,
    NSEC3_TYPE, NSEC_TYPE, RRSIG_TYPE,
};
pub use validate::{validate_response, validate_rrset, DnssecValidation};
