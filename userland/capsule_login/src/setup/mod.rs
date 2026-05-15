mod discover;

use crate::state::Context;

pub fn run() -> Result<Context, &'static str> {
    let keyring_port = discover::lookup_keyring_port()?;
    let desktop_shell_port = discover::lookup_desktop_shell_port()?;
    let compositor_port = discover::lookup_compositor_port()?;
    Ok(Context::new(keyring_port, desktop_shell_port, compositor_port))
}
