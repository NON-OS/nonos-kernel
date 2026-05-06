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

//! A non-installable preview entry — the shape an operator uses to
//! seed dashboard cards before a real `.noxc` package exists. The
//! release advertises `Pending` status, no `package_url`, no
//! publisher signature; install_ready will refuse it.

extern crate alloc;

use ed25519_dalek::VerifyingKey;
use nonos_marketplace_abi::{
    CapsuleRelease, MarketplaceEntry, MarketplaceIndex, PriceKind, PriceModel, TokenInfo,
    ValidationReport, ValidationStatus,
};

use super::key::signing_key;

pub fn preview_entry_index() -> MarketplaceIndex {
    let pubkey = VerifyingKey::from(&signing_key()).to_bytes();
    MarketplaceIndex {
        schema_version: 1,
        operator_id: alloc::string::String::from("test.operator"),
        operator_pubkey: pubkey,
        published_at_ms: 1_700_000_000_000,
        serial: 2,
        entries: alloc::vec![preview_entry()],
        index_signature: alloc::vec::Vec::new(),
    }
}

fn preview_entry() -> MarketplaceEntry {
    MarketplaceEntry {
        listing_id: alloc::string::String::from("preview.demo.v1"),
        capsule_id: [0u8; 32],
        name: alloc::string::String::from("Preview Demo"),
        publisher_name: alloc::string::String::from("0xNOX"),
        publisher_pubkey: [0u8; 32],
        description: alloc::string::String::from("Preview card; not installable yet."),
        price: PriceModel { kind: PriceKind::Free, amount_atomic: 0, period_seconds: 0 },
        token: TokenInfo {
            symbol: alloc::string::String::from("NOX"),
            decimals: 18,
            chain_id: 1,
            contract_address: alloc::vec::Vec::new(),
        },
        releases: alloc::vec![preview_release()],
    }
}

fn preview_release() -> CapsuleRelease {
    CapsuleRelease {
        release_id: alloc::string::String::from("preview-0"),
        manifest_hash: [0u8; 32],
        package_hash: [0u8; 32],
        package_url: alloc::string::String::new(),
        publisher_signature: alloc::vec::Vec::new(),
        supported_arches: alloc::vec![alloc::string::String::from("x86_64-nonos")],
        kernel_abi_min: 1,
        required_capabilities: alloc::vec::Vec::new(),
        validation: ValidationReport {
            status: ValidationStatus::Pending,
            note: alloc::string::String::from("seed preview card"),
            validator_id: alloc::string::String::from("nonos.marketplace.v1"),
            validated_at_ms: 0,
        },
    }
}
