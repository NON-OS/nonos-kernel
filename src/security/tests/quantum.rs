// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Quantum security state tests

extern crate alloc;

use crate::security::policy::capability::quantum::{QuantumParticle, QuantumState};
use crate::test::framework::TestResult;
use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

pub(crate) fn test_quantum_particle_fields() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [0.5, 0.5, 0.5, 0.5],
        spin: 0.5,
        position_uncertainty: 0.1,
        momentum_uncertainty: 0.2,
        last_measurement: 1000,
    };
    if particle.state_vector[0] != 0.5 {
        return TestResult::Fail;
    }
    if particle.spin != 0.5 {
        return TestResult::Fail;
    }
    if particle.position_uncertainty != 0.1 {
        return TestResult::Fail;
    }
    if particle.momentum_uncertainty != 0.2 {
        return TestResult::Fail;
    }
    if particle.last_measurement != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_state_vector_size() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [1.0, 0.0, 0.0, 0.0],
        spin: 0.0,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    if particle.state_vector.len() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_normalized_state() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [1.0, 0.0, 0.0, 0.0],
        spin: 0.5,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    let sum_squares: f64 = particle.state_vector.iter().map(|x| x * x).sum();
    if (sum_squares - 1.0).abs() >= 0.001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_spin_up() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: 0.5,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    if particle.spin != 0.5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_spin_down() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: -0.5,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    if particle.spin != -0.5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_uncertainty_positive() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: 0.0,
        position_uncertainty: 0.5,
        momentum_uncertainty: 0.3,
        last_measurement: 0,
    };
    if particle.position_uncertainty <= 0.0 {
        return TestResult::Fail;
    }
    if particle.momentum_uncertainty <= 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_heisenberg_relation() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: 0.0,
        position_uncertainty: 0.1,
        momentum_uncertainty: 5.0,
        last_measurement: 0,
    };
    let product = particle.position_uncertainty * particle.momentum_uncertainty;
    if product < 0.5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_timestamp() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: 0.0,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: u64::MAX,
    };
    if particle.last_measurement != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_debug() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [0.5, 0.5, 0.5, 0.5],
        spin: 0.5,
        position_uncertainty: 0.1,
        momentum_uncertainty: 0.2,
        last_measurement: 100,
    };
    let debug_str = format!("{:?}", particle);
    if !debug_str.contains("QuantumParticle") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_state_empty_particles() -> TestResult {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0u8; 64],
    };
    if !state.entangled_particles.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_state_with_particles() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [1.0, 0.0, 0.0, 0.0],
        spin: 0.5,
        position_uncertainty: 0.1,
        momentum_uncertainty: 0.2,
        last_measurement: 0,
    };
    let state = QuantumState {
        entangled_particles: alloc::vec![particle],
        decoherence_timer: AtomicU64::new(1000),
        quantum_key: [0xABu8; 64],
    };
    if state.entangled_particles.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_state_key_size() -> TestResult {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0u8; 64],
    };
    if state.quantum_key.len() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_state_decoherence_timer() -> TestResult {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(5000),
        quantum_key: [0u8; 64],
    };
    let timer = state.decoherence_timer.load(core::sync::atomic::Ordering::Relaxed);
    if timer != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_state_debug() -> TestResult {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0u8; 64],
    };
    let debug_str = format!("{:?}", state);
    if !debug_str.contains("QuantumState") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_state_key_all_zeros() -> TestResult {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0u8; 64],
    };
    if !state.quantum_key.iter().all(|&b| b == 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_state_key_all_ones() -> TestResult {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0xFFu8; 64],
    };
    if !state.quantum_key.iter().all(|&b| b == 0xFF) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_superposition() -> TestResult {
    let inv_sqrt_2 = 1.0 / 2.0_f64.sqrt();
    let particle = QuantumParticle {
        state_vector: [inv_sqrt_2, inv_sqrt_2, 0.0, 0.0],
        spin: 0.0,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    let sum_squares: f64 = particle.state_vector.iter().map(|x| x * x).sum();
    if (sum_squares - 1.0).abs() >= 0.001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_state_multiple_particles() -> TestResult {
    let p1 = QuantumParticle {
        state_vector: [1.0, 0.0, 0.0, 0.0],
        spin: 0.5,
        position_uncertainty: 0.1,
        momentum_uncertainty: 0.2,
        last_measurement: 100,
    };
    let p2 = QuantumParticle {
        state_vector: [0.0, 1.0, 0.0, 0.0],
        spin: -0.5,
        position_uncertainty: 0.1,
        momentum_uncertainty: 0.2,
        last_measurement: 200,
    };
    let state = QuantumState {
        entangled_particles: alloc::vec![p1, p2],
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0u8; 64],
    };
    if state.entangled_particles.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_all_fields_zero() -> TestResult {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: 0.0,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    if particle.spin != 0.0 {
        return TestResult::Fail;
    }
    if particle.position_uncertainty != 0.0 {
        return TestResult::Fail;
    }
    if particle.momentum_uncertainty != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_state_timer_atomic_operations() -> TestResult {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(100),
        quantum_key: [0u8; 64],
    };
    state.decoherence_timer.fetch_add(50, core::sync::atomic::Ordering::Relaxed);
    let timer = state.decoherence_timer.load(core::sync::atomic::Ordering::Relaxed);
    if timer != 150 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_quantum_particle_different_states() -> TestResult {
    let ground = QuantumParticle {
        state_vector: [1.0, 0.0, 0.0, 0.0],
        spin: 0.0,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    let excited = QuantumParticle {
        state_vector: [0.0, 1.0, 0.0, 0.0],
        spin: 0.0,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    if ground.state_vector == excited.state_vector {
        return TestResult::Fail;
    }
    TestResult::Pass
}
