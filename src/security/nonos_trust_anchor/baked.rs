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

// Switched to `Some(include_bytes!(...))` once Lane B emits
// .keys/nonos_trust_anchor.policy.bin. While this is None every
// caller that needs the trust anchor returns a loud error rather
// than spawn a capsule against an absent policy.
pub const BAKED_TRUST_ANCHOR_POLICY: Option<&[u8]> = None;
