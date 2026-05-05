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

// Kernel-side capsule manifest. The kernel reads only the fields it
// actually enforces: publisher signature, package/entry hash, caps,
// and the IPC endpoints the capsule will register. Marketplace
// metadata (name, publisher display name, prices, payment policy,
// storage/network/display labels) lives in a userland-extended
// envelope that wraps this manifest; the kernel never parses it.

mod decode;
mod schema;
mod verify;

pub use decode::{decode, DecodeError};
pub use schema::{EndpointDecl, Manifest, ManifestError, Version, MANIFEST_SCHEMA_VERSION};
pub use verify::{verify, VerifiedManifest, VerifyError};
