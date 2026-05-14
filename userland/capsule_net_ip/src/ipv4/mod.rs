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

mod addr;
mod build;
mod checksum;
mod header;
mod parse;
mod proto;

pub use addr::{
    is_broadcast, is_loopback, is_multicast, is_unspecified, mask_with_prefix, same_subnet,
    Ipv4Addr, ANY, BROADCAST, LOOPBACK,
};
pub use build::{build, BuildError, BuildRequest};
pub use checksum::{fold, seal_at};
pub use header::{
    Ipv4Header, CHECKSUM_OFFSET, DEFAULT_TTL, DST_OFFSET, FLAG_DONT_FRAGMENT, FLAG_MORE_FRAGMENTS,
    FRAGMENT_OFFSET_MASK, HDR_LEN_MAX, HDR_LEN_MIN, PROTO_OFFSET, SRC_OFFSET, TOTAL_LEN_OFFSET,
    TTL_OFFSET, VERSION_4,
};
pub use parse::{parse, ParseError};
pub use proto::{Proto, ICMP, TCP, UDP};
