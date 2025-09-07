//! Module runtime definitions

pub enum FaultPolicy {
    Restart,
    Terminate,
    Ignore,
}
