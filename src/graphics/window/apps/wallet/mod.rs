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

/*
 * Wallet application for NONOS.
 *
 * A privacy-focused Ethereum-compatible wallet with stealth address support.
 * Features include:
 * - HD key derivation from master seed
 * - Multiple account management
 * - Send/receive with QR code display
 * - Stealth address generation for private transactions
 * - RLP transaction encoding and signing
 * - Zero-knowledge proof integration for enhanced privacy
 *
 * Key generation uses aggressive entropy collection from 12+ sources
 * to ensure unique wallets even in virtualized or deterministic environments.
 */

extern crate alloc;

mod api;
mod click_locked;
mod click_overview;
mod click_send;
mod input;
mod keyboard;
mod render;
mod render_stealth;
mod render_transactions;
mod render_views;
mod rlp;
mod rpc;
mod state;
mod state_ops;
mod stealth;
mod transaction;
mod types;
mod zk;
mod zk_circuit;
mod zk_helpers;
mod zk_prove;
mod zk_types;

pub use api::{draw, handle_click, handle_key, handle_special_key};

pub(crate) use state::{derive_account, init_wallet, lock_wallet, WALLET_STATE};
pub(crate) use types::format_address;
