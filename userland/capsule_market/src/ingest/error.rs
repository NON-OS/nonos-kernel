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

//! Failures the ingest path can surface. Each variant maps to a
//! distinct errno on the IPC reply so a caller can tell a malformed
//! blob from a stale serial from a refused signature without
//! parsing free-form text.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestError {
    /// Length cap exceeded, premature end, or non-canonical
    /// encoding. Surfaces every `DecodeError` from the ABI codec.
    Malformed,
    /// Index serial is at or below the last serial accepted by
    /// the store. A snapshot from an older publish is refused so
    /// a compromised mirror cannot revive a revoked listing.
    StaleSerial,
    /// Index signature did not validate against the operator
    /// pubkey. The default verifier returns this for every input
    /// until a real Ed25519 backend lands.
    SignatureRefused,
    /// Embedded `operator_pubkey` is not present in the bake-in
    /// trust list. The blob may be perfectly well-formed and
    /// self-consistent — it just was not signed by an operator the
    /// kernel image trusts.
    UntrustedOperator,
}
