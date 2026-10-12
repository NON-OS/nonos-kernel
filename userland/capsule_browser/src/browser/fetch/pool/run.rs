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

//! Stepping the pool's fetches, and letting go of them.

use alloc::vec::Vec;

use super::slots::Pool;
use crate::browser::fetch::run::run;
use crate::browser::fetch::types::Fetch;
use crate::browser::fetch::wire::Wire;

impl Pool {
    /// Step every running fetch, and hand back the ones that ended.
    ///
    /// Each step begins one further along. A tick spends only so long
    /// waiting on proxies (`net::mixnet::pace`), and fetches stepped after
    /// that budget is gone are not asked for anything that tick: always
    /// beginning at the first would leave the last waiting for good.
    pub fn step<W: Wire>(&mut self, w: &mut W, until: i64) -> Vec<Fetch> {
        let n = self.live.len();
        if n > 0 {
            let first = self.turn % n;
            self.turn = self.turn.wrapping_add(1);
            for i in 0..n {
                run(w, &mut self.live[(first + i) % n], until);
            }
        }
        let mut ended = Vec::new();
        let mut at = 0;
        while at < self.live.len() {
            if self.live[at].ended() {
                ended.push(self.live.remove(at));
            } else {
                at += 1;
            }
        }
        ended
    }

    /// Close every running fetch and forget what waits its turn. Kept
    /// connections stay: the next page may well ask the same hosts.
    pub fn cancel_live<W: Wire>(&mut self, w: &mut W) {
        for f in self.live.drain(..) {
            w.close(f.handle);
        }
        self.held.clear();
        self.redirects.clear();
        self.run_order = 0;
        self.scripts = None;
    }

    /// Close everything, kept connections included.
    pub fn cancel_all<W: Wire>(&mut self, w: &mut W) {
        self.cancel_live(w);
        self.close_idle(w);
    }

    /// Close the kept connections, each of which may hold a stream at a
    /// proxy that another tab could use.
    pub fn close_idle<W: Wire>(&mut self, w: &mut W) {
        for idle in self.idle.drain(..) {
            w.close(idle.handle);
        }
    }
}
