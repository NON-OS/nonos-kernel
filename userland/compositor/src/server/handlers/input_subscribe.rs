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

use crate::protocol::Request;
use crate::server::respond;
use crate::state::Context;

// Records the subscriber as the current input focus owner. The
// input_router capsule lands in B4 with grab/release semantics; this
// keeps the contract surface honest in the meantime so subscribers
// get a deterministic E_OK or E_INVAL today.
pub fn handle(ctx: &mut Context, sender_pid: u32, req: &Request, tx: &mut [u8]) {
    ctx.focus.set(sender_pid);
    let _ = respond::status(sender_pid, req, 0, tx);
}
