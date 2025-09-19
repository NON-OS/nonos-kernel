//! NØNOS IPC Policy Enforcement Layer
//!
//! Provides robust, zero-trust, capability-driven access control for message routing and
//! channel provisioning between sandboxed `.mod` runtime environments. This system enables
//! enforceable isolation boundaries and structured privilege elevation.

use crate::syscall::capabilities::{Capability, CapabilityToken};
use crate::ipc::message::{IpcEnvelope, MessageType, MsgFlags};
use crate::log::logger::{log_info, log_warn};

/// IPC routing policy trait
pub trait IpcPolicy {
    /// Determines whether a message is allowed from sender to recipient
    fn allow_message(&self, envelope: &IpcEnvelope, token: &CapabilityToken) -> bool;

    /// Determines whether an IPC channel may be opened between two modules
    fn allow_channel(&self, from: &str, to: &str, token: &CapabilityToken) -> bool;

    /// Optional logging hook for policy violations
    fn on_violation(&self, kind: PolicyViolation, envelope: Option<&IpcEnvelope>);
}

/// Enum describing policy violation types
#[derive(Debug, Clone)]
pub enum PolicyViolation {
    MissingIpcCapability,
    SystemOnlyAccessDenied,
    CapabilityMessageDenied,
    SelfChannelDenied,
    Unknown,
}

/// Default hardened zero-trust IPC policy
pub struct DefaultIpcPolicy;

impl IpcPolicy for DefaultIpcPolicy {
    fn allow_message(&self, envelope: &IpcEnvelope, token: &CapabilityToken) -> bool {
        if !token.permissions.contains(&Capability::IPC) {
            self.on_violation(PolicyViolation::MissingIpcCapability, Some(envelope));
            return false;
        }

        if envelope.message_type == MessageType::System {
            if !token.permissions.contains(&Capability::CoreExec) {
                self.on_violation(PolicyViolation::SystemOnlyAccessDenied, Some(envelope));
                return false;
            }
        }

        match envelope.message_type {
            MessageType::Capability | MessageType::Auth => {
                if !token.permissions.contains(&Capability::Crypto) {
                    self.on_violation(PolicyViolation::CapabilityMessageDenied, Some(envelope));
                    return false;
                }
            }
            _ => {}
        }

        true
    }

    fn allow_channel(&self, from: &str, to: &str, token: &CapabilityToken) -> bool {
        if !token.permissions.contains(&Capability::IPC) {
            self.on_violation(PolicyViolation::MissingIpcCapability, None);
            return false;
        }
        if from == to {
            self.on_violation(PolicyViolation::SelfChannelDenied, None);
            return false;
        }
        true
    }

    fn on_violation(&self, kind: PolicyViolation, envelope: Option<&IpcEnvelope>) {
        // TODO: Hook into telemetry subsystem
        log_warn!("Policy violation: {:?}, Msg = {:?}", kind, envelope);
    }
}

/// Globally mutable IPC policy instance
/// Replaceable during runtime boot via system call or trusted module API.
pub static mut ACTIVE_POLICY: &dyn IpcPolicy = &DefaultIpcPolicy;
