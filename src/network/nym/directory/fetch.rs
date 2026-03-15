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

use crate::network::nym::error::NymError;

pub fn fetch_topology() -> Result<(), NymError> {
    let cache = super::cache::get_directory_cache().lock();
    let need_mixnodes = cache.is_mixnodes_stale();
    let need_gateways = cache.is_gateways_stale();
    drop(cache);
    if need_mixnodes {
        super::mixnodes::fetch_mixnodes()?;
    }
    if need_gateways {
        super::gateways::fetch_gateways()?;
    }
    Ok(())
}

pub fn refresh_all() -> Result<(), NymError> {
    {
        let mut cache = super::cache::get_directory_cache().lock();
        cache.clear();
    }
    fetch_topology()
}

pub fn ensure_topology() -> Result<(), NymError> {
    let cache = super::cache::get_directory_cache().lock();
    if cache.mixnodes.is_empty() || cache.gateways.is_empty() {
        drop(cache);
        return fetch_topology();
    }
    Ok(())
}
