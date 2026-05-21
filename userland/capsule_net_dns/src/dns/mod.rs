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

mod cache;
mod header;
mod name;
mod query;
mod response;
mod types;

pub use cache::{hash, Cache, CacheEntry, ENTRY_CAP, NAME_BYTES};
pub use header::{
    Header, FLAG_AA, FLAG_QR, FLAG_RA, FLAG_RD, FLAG_TC, HDR_LEN, RCODE_FORMAT, RCODE_MASK,
    RCODE_NOTIMP, RCODE_NO_ERROR, RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL,
};
pub use name::{encode, skip, NameError};
pub use query::{build_a_query, build_aaaa_query, BuildError};
pub use response::{first_address, Answer, ParseError};
pub use types::{
    Question, ResourceRecord, CLASS_IN, LABEL_MAX, NAME_MAX, POINTER_MASK, TYPE_A, TYPE_AAAA,
    TYPE_CNAME, TYPE_MX, TYPE_NS, TYPE_PTR, TYPE_TXT,
};
