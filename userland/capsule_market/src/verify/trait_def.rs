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

//! Signature-verification interface the capsule talks to. The
//! capsule never inlines crypto; a verifier implementation
//! (eventually backed by capsule_crypto's Ed25519 verify) plugs
//! in here so the policy logic can stay independent of the
//! cryptographic backend.

/// Verdict the verifier returns. The default `RejectAll` returns
/// `Refused` for every call so an index served by an operator
/// whose key the system has not yet learned to trust never
/// promotes to `install_ready=true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Signature checks against the supplied pubkey.
    Accepted,
    /// Signature does not check, or no verifier is plugged in.
    Refused,
}

pub trait Verifier {
    /// Verify `signature` against `signed_bytes` using the public
    /// key `pubkey`. Implementations must return `Refused` on any
    /// length mismatch, malformed signature, or backend failure;
    /// the marketplace policy layer treats `Accepted` as the
    /// only path to install readiness.
    fn verify(&self, signed_bytes: &[u8], signature: &[u8], pubkey: &[u8; 32]) -> Verdict;
}
