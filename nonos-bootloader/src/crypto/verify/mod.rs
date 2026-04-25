// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod bytes;
mod capsule;
mod error;
mod metadata;
mod simple;
mod status;

pub use bytes::verify_signature_bytes;
pub use capsule::verify_signature_full;
pub use error::VerifyError;
pub use metadata::CapsuleMetadata;
pub use simple::verify_signature;
pub use status::{CertificateStatus, SignatureStatus};
pub const SIG_LEN: usize = 64;
