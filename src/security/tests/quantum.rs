// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::security::policy::capability::quantum::{QuantumState, QuantumParticle};
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

#[test]
fn test_quantum_particle_fields() {
    let particle = QuantumParticle {
        state_vector: [0.5, 0.5, 0.5, 0.5],
        spin: 0.5,
        position_uncertainty: 0.1,
        momentum_uncertainty: 0.2,
        last_measurement: 1000,
    };
    assert_eq!(particle.state_vector[0], 0.5);
    assert_eq!(particle.spin, 0.5);
    assert_eq!(particle.position_uncertainty, 0.1);
    assert_eq!(particle.momentum_uncertainty, 0.2);
    assert_eq!(particle.last_measurement, 1000);
}

#[test]
fn test_quantum_particle_state_vector_size() {
    let particle = QuantumParticle {
        state_vector: [1.0, 0.0, 0.0, 0.0],
        spin: 0.0,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    assert_eq!(particle.state_vector.len(), 4);
}

#[test]
fn test_quantum_particle_normalized_state() {
    let particle = QuantumParticle {
        state_vector: [1.0, 0.0, 0.0, 0.0],
        spin: 0.5,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    let sum_squares: f64 = particle.state_vector.iter().map(|x| x * x).sum();
    assert!((sum_squares - 1.0).abs() < 0.001);
}

#[test]
fn test_quantum_particle_spin_up() {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: 0.5,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    assert_eq!(particle.spin, 0.5);
}

#[test]
fn test_quantum_particle_spin_down() {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: -0.5,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    assert_eq!(particle.spin, -0.5);
}

#[test]
fn test_quantum_particle_uncertainty_positive() {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: 0.0,
        position_uncertainty: 0.5,
        momentum_uncertainty: 0.3,
        last_measurement: 0,
    };
    assert!(particle.position_uncertainty > 0.0);
    assert!(particle.momentum_uncertainty > 0.0);
}

#[test]
fn test_quantum_particle_heisenberg_relation() {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: 0.0,
        position_uncertainty: 0.1,
        momentum_uncertainty: 5.0,
        last_measurement: 0,
    };
    let product = particle.position_uncertainty * particle.momentum_uncertainty;
    assert!(product >= 0.5);
}

#[test]
fn test_quantum_particle_timestamp() {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: 0.0,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: u64::MAX,
    };
    assert_eq!(particle.last_measurement, u64::MAX);
}

#[test]
fn test_quantum_particle_debug() {
    let particle = QuantumParticle {
        state_vector: [0.5, 0.5, 0.5, 0.5],
        spin: 0.5,
        position_uncertainty: 0.1,
        momentum_uncertainty: 0.2,
        last_measurement: 100,
    };
    let debug_str = alloc::format!("{:?}", particle);
    assert!(debug_str.contains("QuantumParticle"));
}

#[test]
fn test_quantum_state_empty_particles() {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0u8; 64],
    };
    assert!(state.entangled_particles.is_empty());
}

#[test]
fn test_quantum_state_with_particles() {
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
    assert_eq!(state.entangled_particles.len(), 1);
}

#[test]
fn test_quantum_state_key_size() {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0u8; 64],
    };
    assert_eq!(state.quantum_key.len(), 64);
}

#[test]
fn test_quantum_state_decoherence_timer() {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(5000),
        quantum_key: [0u8; 64],
    };
    let timer = state.decoherence_timer.load(core::sync::atomic::Ordering::Relaxed);
    assert_eq!(timer, 5000);
}

#[test]
fn test_quantum_state_debug() {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0u8; 64],
    };
    let debug_str = alloc::format!("{:?}", state);
    assert!(debug_str.contains("QuantumState"));
}

#[test]
fn test_quantum_state_key_all_zeros() {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0u8; 64],
    };
    assert!(state.quantum_key.iter().all(|&b| b == 0));
}

#[test]
fn test_quantum_state_key_all_ones() {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(0),
        quantum_key: [0xFFu8; 64],
    };
    assert!(state.quantum_key.iter().all(|&b| b == 0xFF));
}

#[test]
fn test_quantum_particle_superposition() {
    let inv_sqrt_2 = 1.0 / 2.0_f64.sqrt();
    let particle = QuantumParticle {
        state_vector: [inv_sqrt_2, inv_sqrt_2, 0.0, 0.0],
        spin: 0.0,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    let sum_squares: f64 = particle.state_vector.iter().map(|x| x * x).sum();
    assert!((sum_squares - 1.0).abs() < 0.001);
}

#[test]
fn test_quantum_state_multiple_particles() {
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
    assert_eq!(state.entangled_particles.len(), 2);
}

#[test]
fn test_quantum_particle_all_fields_zero() {
    let particle = QuantumParticle {
        state_vector: [0.0; 4],
        spin: 0.0,
        position_uncertainty: 0.0,
        momentum_uncertainty: 0.0,
        last_measurement: 0,
    };
    assert_eq!(particle.spin, 0.0);
    assert_eq!(particle.position_uncertainty, 0.0);
    assert_eq!(particle.momentum_uncertainty, 0.0);
}

#[test]
fn test_quantum_state_timer_atomic_operations() {
    let state = QuantumState {
        entangled_particles: Vec::new(),
        decoherence_timer: AtomicU64::new(100),
        quantum_key: [0u8; 64],
    };
    state.decoherence_timer.fetch_add(50, core::sync::atomic::Ordering::Relaxed);
    let timer = state.decoherence_timer.load(core::sync::atomic::Ordering::Relaxed);
    assert_eq!(timer, 150);
}

#[test]
fn test_quantum_particle_different_states() {
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
    assert_ne!(ground.state_vector, excited.state_vector);
}

