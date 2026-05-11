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

// Non-optional on purpose: the kernel cannot ship without a trust
// anchor. The policy blob lives under nonos-data/trust/ (committed
// public artifact); a missing file must break the build, not be
// papered over with an Option/None or an empty slice — both would
// let an unverified capsule path quietly take over at runtime.
pub const BAKED_TRUST_ANCHOR_POLICY: &[u8] =
    include_bytes!("../../../nonos-data/trust/policy/nonos_trust_anchor.policy.bin");
