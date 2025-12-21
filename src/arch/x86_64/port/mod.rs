// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! NØNOS x86_64 Port I/O Module
//!
//! This module provides low-level port I/O operations for x86_64.

mod nonos_port;

// ============================================================================
// Re-export everything from nonos_port
// ============================================================================

// Error types
pub use nonos_port::PortError;

// Well-known ports
pub use nonos_port::ports;

// Traits
pub use nonos_port::PortValue;

// Port wrappers
pub use nonos_port::Port;
pub use nonos_port::PortRange;
pub use nonos_port::PortReadOnly;
pub use nonos_port::PortWriteOnly;

// Manager & statistics
pub use nonos_port::PortManager;
pub use nonos_port::PortStats;
pub use nonos_port::PORT_MANAGER;

// Raw I/O functions
pub use nonos_port::inb;
pub use nonos_port::inl;
pub use nonos_port::inw;
pub use nonos_port::outb;
pub use nonos_port::outl;
pub use nonos_port::outw;

// With delay variants
pub use nonos_port::inb_p;
pub use nonos_port::outb_p;

// String I/O
pub use nonos_port::insb;
pub use nonos_port::insl;
pub use nonos_port::insw;
pub use nonos_port::outsb;
pub use nonos_port::outsl;
pub use nonos_port::outsw;

// I/O delay
pub use nonos_port::io_delay;
pub use nonos_port::io_delay_n;

// Public API
pub use nonos_port::init;
pub use nonos_port::port;
pub use nonos_port::port_read_only;
pub use nonos_port::port_write_only;
pub use nonos_port::release_range;
pub use nonos_port::reserve_range;
pub use nonos_port::stats;
