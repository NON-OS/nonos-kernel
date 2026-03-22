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

mod chain;
mod constraints;
mod rsa_parse;
mod sig_ed_ecdsa;
mod signature;

pub(crate) use chain::verify_chain;
pub(crate) use constraints::check_basic_constraints_end_entity;
pub(crate) use constraints::{check_ca_constraints, check_path_len_constraints, check_eku_server_auth, check_leaf_key_usage};
pub(crate) use signature::{verify_self_signed, verify_signature, verify_signature_with_spki_der};
