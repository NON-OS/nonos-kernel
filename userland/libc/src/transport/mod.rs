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

mod envelope;
mod error;
mod respond;
mod round_trip;
mod seq;

pub use envelope::{read_request_v2, write_request_v2, RequestV2, HDR_LEN_V2, VERSION_V2};
pub use error::TransportError;
pub use respond::respond;
pub use round_trip::{round_trip, Response, RoundTrip};
pub use seq::Counter;
