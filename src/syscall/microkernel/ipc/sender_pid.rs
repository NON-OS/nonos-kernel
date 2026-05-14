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

// `kernel_route_ipc` stamps `proc.<pid>` on every routed message's
// `from` field. Parse it back into a u32. A kernel-internal sender
// (no `proc.` prefix) returns 0 so receivers can tell apart capsule
// callers from kernel-driven deliveries.
pub(super) fn from_envelope(from: &str) -> u32 {
    from.strip_prefix("proc.").and_then(|s| s.parse::<u32>().ok()).unwrap_or(0)
}
