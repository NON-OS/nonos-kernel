pub mod nonos_timer;
pub mod tsc;
pub mod hpet;
pub mod pit;
pub mod rtc;
// pub mod test; // Uncomment until timer unit tests

// Shared constants, types, or traits for the time subsystem can be defined here.

pub use tsc::rdtsc as tsc_now;
