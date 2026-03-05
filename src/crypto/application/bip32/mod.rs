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

//! BIP-32 Hierarchical Deterministic wallet derivation.

extern crate alloc;

pub mod derive;
pub mod extended_key;
pub mod path;

pub use derive::{derive_master_key, derive_child};
pub use extended_key::{ExtendedPrivateKey, ExtendedPublicKey};
pub use path::{DerivationPath, PathComponent, BIP44_ETH_PATH};
