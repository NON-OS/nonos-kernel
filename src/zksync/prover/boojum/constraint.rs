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
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub enum Gate {
    Add { a: usize, b: usize, c: usize },
    Mul { a: usize, b: usize, c: usize },
    Const { wire: usize, value: GoldilocksField },
    PublicInput { wire: usize, index: usize },
    Poseidon { inputs: [usize; 12], outputs: [usize; 4] },
}

pub struct ConstraintSystem {
    gates: Vec<Gate>,
    num_wires: usize,
    num_public_inputs: usize,
}

impl ConstraintSystem {
    pub fn new() -> Self {
        Self { gates: Vec::new(), num_wires: 0, num_public_inputs: 0 }
    }

    pub fn allocate_wire(&mut self) -> usize {
        let wire = self.num_wires;
        self.num_wires += 1;
        wire
    }

    pub fn allocate_public_input(&mut self) -> usize {
        let wire = self.allocate_wire();
        let index = self.num_public_inputs;
        self.num_public_inputs += 1;
        self.gates.push(Gate::PublicInput { wire, index });
        wire
    }

    pub fn add_addition(&mut self, a: usize, b: usize) -> usize {
        let c = self.allocate_wire();
        self.gates.push(Gate::Add { a, b, c });
        c
    }

    pub fn add_multiplication(&mut self, a: usize, b: usize) -> usize {
        let c = self.allocate_wire();
        self.gates.push(Gate::Mul { a, b, c });
        c
    }

    pub fn add_constant(&mut self, value: GoldilocksField) -> usize {
        let wire = self.allocate_wire();
        self.gates.push(Gate::Const { wire, value });
        wire
    }

    pub fn add_poseidon(&mut self, inputs: [usize; 12]) -> [usize; 4] {
        let outputs = [
            self.allocate_wire(),
            self.allocate_wire(),
            self.allocate_wire(),
            self.allocate_wire(),
        ];
        self.gates.push(Gate::Poseidon { inputs, outputs });
        outputs
    }

    pub fn verify_witness(
        &self,
        witness: &[GoldilocksField],
        public_inputs: &[GoldilocksField],
    ) -> bool {
        if witness.len() < self.num_wires {
            return false;
        }
        for gate in &self.gates {
            match gate {
                Gate::Add { a, b, c } => {
                    if witness[*a] + witness[*b] != witness[*c] {
                        return false;
                    }
                }
                Gate::Mul { a, b, c } => {
                    if witness[*a] * witness[*b] != witness[*c] {
                        return false;
                    }
                }
                Gate::Const { wire, value } => {
                    if witness[*wire] != *value {
                        return false;
                    }
                }
                Gate::PublicInput { wire, index } => {
                    if *index >= public_inputs.len() {
                        return false;
                    }
                    if witness[*wire] != public_inputs[*index] {
                        return false;
                    }
                }
                Gate::Poseidon { .. } => {}
            }
        }
        true
    }

    pub fn num_gates(&self) -> usize {
        self.gates.len()
    }
    pub fn num_wires(&self) -> usize {
        self.num_wires
    }
    pub fn num_public_inputs(&self) -> usize {
        self.num_public_inputs
    }
}

impl Default for ConstraintSystem {
    fn default() -> Self {
        Self::new()
    }
}
