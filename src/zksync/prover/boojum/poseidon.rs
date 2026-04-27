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

use super::field::GoldilocksField;

const STATE_WIDTH: usize = 12;
const RATE: usize = 8;
const CAPACITY: usize = 4;
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 22;
const ALPHA: u64 = 7;

pub struct PoseidonHash {
    state: [GoldilocksField; STATE_WIDTH],
    absorbed: usize,
}

impl Default for PoseidonHash {
    fn default() -> Self {
        Self { state: [GoldilocksField::ZERO; STATE_WIDTH], absorbed: 0 }
    }
}

impl PoseidonHash {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn absorb(&mut self, input: &[GoldilocksField]) {
        for &elem in input {
            self.state[self.absorbed] = self.state[self.absorbed] + elem;
            self.absorbed += 1;
            if self.absorbed == RATE {
                self.permutation();
                self.absorbed = 0;
            }
        }
    }

    pub fn squeeze(&mut self) -> [GoldilocksField; CAPACITY] {
        if self.absorbed > 0 {
            self.permutation();
            self.absorbed = 0;
        }
        let mut out = [GoldilocksField::ZERO; CAPACITY];
        out.copy_from_slice(&self.state[..CAPACITY]);
        out
    }

    fn permutation(&mut self) {
        let mut round_ctr = 0;
        for _ in 0..(FULL_ROUNDS / 2) {
            self.full_round(round_ctr);
            round_ctr += 1;
        }
        for _ in 0..PARTIAL_ROUNDS {
            self.partial_round(round_ctr);
            round_ctr += 1;
        }
        for _ in 0..(FULL_ROUNDS / 2) {
            self.full_round(round_ctr);
            round_ctr += 1;
        }
    }

    fn full_round(&mut self, round: usize) {
        self.add_round_constants(round);
        for i in 0..STATE_WIDTH {
            self.state[i] = self.sbox(self.state[i]);
        }
        self.mds_mix();
    }

    fn partial_round(&mut self, round: usize) {
        self.add_round_constants(round);
        self.state[0] = self.sbox(self.state[0]);
        self.mds_mix();
    }

    #[inline]
    fn sbox(&self, x: GoldilocksField) -> GoldilocksField {
        let x2 = x * x;
        let x4 = x2 * x2;
        let x6 = x4 * x2;
        x6 * x
    }

    fn add_round_constants(&mut self, round: usize) {
        for i in 0..STATE_WIDTH {
            let rc = GoldilocksField::new((round * STATE_WIDTH + i + 1) as u64);
            self.state[i] = self.state[i] + rc;
        }
    }

    fn mds_mix(&mut self) {
        let mut new_state = [GoldilocksField::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                let coeff = GoldilocksField::new(((i + j) % STATE_WIDTH + 1) as u64);
                new_state[i] = new_state[i] + coeff * self.state[j];
            }
        }
        self.state = new_state;
    }
}

pub fn poseidon_hash(input: &[GoldilocksField]) -> [GoldilocksField; CAPACITY] {
    let mut hasher = PoseidonHash::new();
    hasher.absorb(input);
    hasher.squeeze()
}
