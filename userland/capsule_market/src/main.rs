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

#![no_std]
#![no_main]

extern crate alloc;

mod bootstrap_trust;
mod fixture;
mod ingest;
mod install_ready;
mod protocol;
mod server;
mod store;
mod verify;

use nonos_libc::{mk_exit, heap_init};

use crate::store::Store;

// Default verifier routes through capsule_crypto's
// `OP_ED25519_VERIFY` op via the kernel's `CryptoEd25519Verify`
// syscall. The `offline-verify` feature swaps in the `RejectAll`
// fallback for offline builds where capsule_crypto is not running;
// every signed index is refused under that fallback, which keeps
// install readiness honest.
#[cfg(not(feature = "offline-verify"))]
use crate::verify::CryptoVerifier as DefaultVerifier;

#[cfg(feature = "offline-verify")]
use crate::verify::RejectAll as DefaultVerifier;

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    if heap_init().is_err() {
        mk_exit(1);
    }

    let mut store = Store::empty();
    let verifier = DefaultVerifier;

    #[cfg(feature = "dev-fixture")]
    seed_dev_fixture(&mut store);

    server::run(&mut store, &verifier);
}

#[cfg(feature = "dev-fixture")]
fn seed_dev_fixture(store: &mut Store) {
    let blob = fixture::build();
    if let Ok(v) = crate::ingest::load_unsigned(&blob) {
        store.install(v.index, v.signature_verified);
    }
}
