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

//! Default verifier. Refuses every signature, regardless of input.
//! The capsule ships with this verifier wired in until a real
//! Ed25519 backend (likely an extension to capsule_crypto)
//! replaces it; the conservative default keeps `install_ready`
//! at `false` everywhere a real signature would otherwise be
//! checked, which is the correct trust posture for a system
//! that has not yet been told whose signatures to honour.

use super::trait_def::{Verdict, Verifier};

pub struct RejectAll;

impl Verifier for RejectAll {
    fn verify(&self, _signed_bytes: &[u8], _signature: &[u8], _pubkey: &[u8; 32]) -> Verdict {
        Verdict::Refused
    }
}
