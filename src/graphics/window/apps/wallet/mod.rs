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

extern crate alloc;

mod api;
mod click_locked;
mod click_overview;
mod click_send;
mod click_zksync;
mod input;
mod keyboard;
mod network;
mod render;
mod render_header;
mod render_locked;
mod render_receive;
mod render_send;
mod render_sidebar;
mod render_status;
mod render_stealth;
mod render_transactions;
mod render_utils;
mod render_views;
mod render_zksync;
mod rlp;
mod rpc;
mod rpc_endpoints;
mod rpc_parse;
mod staking;
mod state;
mod state_ops;
mod stealth;
mod transaction;
mod transaction_parse;
mod transaction_sign;
mod types;
mod zk;
mod zk_circuit;
mod zk_circuit_adv;
mod zk_helpers;
mod zk_prove;
mod zk_prove_adv;
mod zk_types;

pub use api::{draw, handle_click, handle_key, handle_special_key, send_nox_to};
pub(crate) use state::{derive_account, init_wallet, lock_wallet, WALLET_STATE};
pub(crate) use types::format_address;
