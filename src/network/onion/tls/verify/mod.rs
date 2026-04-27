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

mod hostname;
mod https;
mod https_check;
mod init;
mod tor;
mod traits;
mod x509_wrap;

pub use https::{HttpsCertVerifier, HTTPS_CERT_VERIFIER};
pub use init::init_tls_stack_production;
pub use tor::{StrictTorLinkVerifier, STRICT_TOR_LINK_VERIFIER};
pub use traits::{get_cert_verifier, init_tls_cert_verifier, CertVerifier};
pub use x509_wrap::X509;
