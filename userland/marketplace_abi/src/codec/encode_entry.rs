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

use super::writer::Writer;
use super::{encode_price, encode_release, encode_token};
use crate::types::MarketplaceEntry;

pub(super) fn write(w: &mut Writer<'_>, entry: &MarketplaceEntry) {
    w.lp_string(&entry.listing_id);
    w.fixed(&entry.capsule_id);
    w.lp_string(&entry.name);
    w.lp_string(&entry.publisher_name);
    w.fixed(&entry.publisher_pubkey);
    w.lp_string(&entry.description);

    encode_price::write(w, &entry.price);
    encode_token::write(w, &entry.token);

    w.u32(entry.releases.len() as u32);
    for release in &entry.releases {
        encode_release::write(w, release);
    }
}
