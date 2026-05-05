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

// Capsule-routed handlers active in the microkernel build: hash
// forwards to `crypto_capsule::client`; random to
// `entropy_capsule::client`. The remaining Linux-shape handlers
// (AEAD seal/open, Ed25519 sign/verify, key-gen, ZK prove/verify)
// still call kernel-resident engines and are gated until each lands
// a capsule client.
mod hash;
mod random;

pub use hash::handle_crypto_hash;
pub use random::handle_crypto_random;

