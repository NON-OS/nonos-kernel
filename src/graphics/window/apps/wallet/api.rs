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

use super::{
    network::chain_id,
    rpc,
    state::WALLET_STATE,
    transaction_parse::{build_erc20_transfer_data, derive_signing_key},
    transaction_sign::build_and_sign_contract_tx,
};
use crate::graphics::window::text_editor::SpecialKey;

pub fn draw(x: u32, y: u32, w: u32, h: u32) {
    super::render::draw(x, y, w, h);
}

pub fn handle_click(wx: u32, wy: u32, ww: u32, wh: u32, cx: i32, cy: i32) -> bool {
    super::input::handle_click(wx, wy, ww, wh, cx, cy)
}

pub fn handle_key(ch: u8) {
    super::input::handle_key(ch);
}

pub fn handle_special_key(key: SpecialKey) {
    super::input::handle_special_key(key);
}

pub fn send_nox_to(to: &[u8; 20], amount: u128) -> Result<[u8; 32], &'static [u8]> {
    if !rpc::is_rpc_available() {
        return Err(b"No network");
    }
    let s = WALLET_STATE.lock();
    if !s.unlocked {
        return Err(b"Wallet locked");
    }
    let mk = s.master_key.ok_or(b"No master key" as &[u8])?;
    let (from, idx) =
        s.get_active_account().map(|a| (a.address, a.index)).ok_or(b"No account" as &[u8])?;
    drop(s);
    let nonce = rpc::fetch_nonce(&from).unwrap_or(0);
    let gp = rpc::fetch_gas_price().unwrap_or(20_000_000_000);
    let sk = derive_signing_key(&mk, idx);
    let data = build_erc20_transfer_data(to, amount);
    let contract = super::network::nox_contract();
    let tx = build_and_sign_contract_tx(&contract, 0, &data, nonce, gp, 100000, chain_id(), &sk)?;
    rpc::send_raw_transaction(&tx).map_err(|_| b"Broadcast failed" as &[u8])
}
