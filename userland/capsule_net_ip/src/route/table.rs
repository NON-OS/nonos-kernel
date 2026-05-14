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

use spin::RwLock;

use crate::ipv4::{same_subnet, Ipv4Addr};

use super::entry::Route;

pub const TABLE_CAP: usize = 16;

pub struct Table {
    entries: RwLock<[Option<Route>; TABLE_CAP]>,
}

impl Table {
    pub const fn new() -> Self {
        Self { entries: RwLock::new([None; TABLE_CAP]) }
    }

    pub fn install(&self, r: Route) -> Result<(), ()> {
        let mut w = self.entries.write();
        for slot in w.iter_mut() {
            if slot.is_none() {
                *slot = Some(r);
                return Ok(());
            }
        }
        Err(())
    }

    pub fn clear(&self) {
        *self.entries.write() = [None; TABLE_CAP];
    }

    // Longest-prefix match. Returns the best matching route's
    // gateway (None means destination is on-link). On miss the
    // caller may fall back to a default route inserted with
    // prefix=0.
    pub fn lookup(&self, dst: &Ipv4Addr) -> Option<Route> {
        let r = self.entries.read();
        let mut best: Option<Route> = None;
        for slot in r.iter() {
            if let Some(route) = slot {
                if route.prefix == 0 {
                    if best.is_none() {
                        best = Some(*route);
                    }
                } else if same_subnet(dst, &route.network, route.prefix) {
                    if best.map(|b| b.prefix < route.prefix).unwrap_or(true) {
                        best = Some(*route);
                    }
                }
            }
        }
        best
    }
}

pub static ROUTES: Table = Table::new();
