mod decode;
mod encode;
mod errno;
mod header;
mod limits;
mod ops;

pub use decode::parse;
pub use encode::{response_header, write_status};
pub use errno::{E_BAD_LEN, E_BAD_MAGIC, E_BAD_OP, E_BAD_VERSION, E_INVAL, E_RANGE};
pub use header::{Request, HDR_LEN, MAGIC, VERSION};
pub use limits::{IPC_PAYLOAD_MAX, MAX_DEPTH, MAX_ENTRY_BYTES, MAX_TOTAL_BYTES, STATUS_LEN};
pub use ops::{OP_CLEAR, OP_COPY, OP_HEALTHCHECK, OP_HISTORY_GET, OP_HISTORY_LIST, OP_PASTE};
