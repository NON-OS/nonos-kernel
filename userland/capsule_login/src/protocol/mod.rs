mod decode;
mod encode;
mod errno;
mod header;
mod limits;
mod ops;

pub use decode::parse;
pub use encode::{response_header, write_status};
pub use errno::{E_AUTH, E_BAD_OP, E_BUSY, E_INVAL, E_NOTREADY};
pub use header::{Request, HDR_LEN, MAGIC, VERSION};
pub use limits::{IPC_PAYLOAD_MAX, START_SESSION_REQ_LEN, STATE_PAYLOAD_LEN, STATUS_LEN};
pub use ops::{OP_END_SESSION, OP_GET_STATE, OP_HEALTHCHECK, OP_START_SESSION};
