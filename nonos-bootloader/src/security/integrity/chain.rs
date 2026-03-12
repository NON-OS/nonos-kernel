// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
 * Boot Integrity Chain.
 *
 * Builds a cryptographic chain of measurements during boot:
 * 1. Bootloader self-hash
 * 2. Security policy state
 * 3. Kernel hash
 * 4. Signature verification result
 * 5. ZK proof verification result
 * 6. Final boot state
 *
 * Each link commits to all previous links, preventing tampering.
 */

use spin::Mutex;

const DS_CHAIN: &str = "NONOS:INTEGRITY:CHAIN:v1";
const MAX_CHAIN_LINKS: usize = 16;

#[derive(Clone, Copy)]
pub struct ChainLink {
    pub stage: BootStage,
    pub measurement: [u8; 32],
    pub cumulative: [u8; 32],
    pub timestamp: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootStage {
    Init = 0,
    UefiServices = 1,
    SecurityPolicy = 2,
    HardwareDiscovery = 3,
    KernelLoad = 4,
    CryptoVerify = 5,
    ZkAttestation = 6,
    ElfParse = 7,
    HandoffPrepare = 8,
    ExitBootServices = 9,
    KernelEntry = 10,
}

impl ChainLink {
    const fn empty() -> Self {
        Self {
            stage: BootStage::Init,
            measurement: [0u8; 32],
            cumulative: [0u8; 32],
            timestamp: 0,
        }
    }
}

pub struct IntegrityChain {
    links: [ChainLink; MAX_CHAIN_LINKS],
    count: usize,
    sealed: bool,
}

impl IntegrityChain {
    pub const fn new() -> Self {
        Self {
            links: [ChainLink::empty(); MAX_CHAIN_LINKS],
            count: 0,
            sealed: false,
        }
    }

    pub fn extend(&mut self, stage: BootStage, data: &[u8], timestamp: u64) -> Option<[u8; 32]> {
        if self.sealed || self.count >= MAX_CHAIN_LINKS {
            return None;
        }

        let measurement = compute_measurement(data);

        let prev_cumulative = if self.count > 0 {
            self.links[self.count - 1].cumulative
        } else {
            [0u8; 32]
        };

        let cumulative = chain_hash(&prev_cumulative, &measurement, stage as u8);

        self.links[self.count] = ChainLink {
            stage,
            measurement,
            cumulative,
            timestamp,
        };
        self.count += 1;

        Some(cumulative)
    }

    pub fn seal(&mut self) {
        self.sealed = true;
    }

    pub fn get_final_hash(&self) -> Option<[u8; 32]> {
        if self.count == 0 {
            return None;
        }
        Some(self.links[self.count - 1].cumulative)
    }

    pub fn verify_chain(&self) -> bool {
        if self.count == 0 {
            return true;
        }

        let mut prev = [0u8; 32];

        for i in 0..self.count {
            let link = &self.links[i];
            let expected = chain_hash(&prev, &link.measurement, link.stage as u8);

            if !constant_time_eq_32(&expected, &link.cumulative) {
                return false;
            }

            prev = link.cumulative;
        }

        true
    }

    pub fn get_link(&self, stage: BootStage) -> Option<&ChainLink> {
        for i in 0..self.count {
            if self.links[i].stage == stage {
                return Some(&self.links[i]);
            }
        }
        None
    }
}

fn compute_measurement(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DS_CHAIN);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

fn chain_hash(prev: &[u8; 32], measurement: &[u8; 32], stage: u8) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DS_CHAIN);
    hasher.update(prev);
    hasher.update(measurement);
    hasher.update(&[stage]);
    *hasher.finalize().as_bytes()
}

#[inline(never)]
fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub static INTEGRITY_CHAIN: Mutex<IntegrityChain> = Mutex::new(IntegrityChain::new());

pub fn record_stage(stage: BootStage, data: &[u8], timestamp: u64) -> Option<[u8; 32]> {
    let mut chain = INTEGRITY_CHAIN.lock();
    chain.extend(stage, data, timestamp)
}

pub fn get_boot_integrity_hash() -> Option<[u8; 32]> {
    let chain = INTEGRITY_CHAIN.lock();
    chain.get_final_hash()
}

pub fn seal_chain() {
    let mut chain = INTEGRITY_CHAIN.lock();
    chain.seal();
}

pub fn verify_integrity() -> bool {
    let chain = INTEGRITY_CHAIN.lock();
    chain.verify_chain()
}
