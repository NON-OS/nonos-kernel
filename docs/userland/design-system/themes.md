# Themes: from Settings to every app

## The design

1. Settings gets two rows in `capsule_settings/src/settings/schema/blocks/appearance.rs`:
   `Row::Field(Field::Theme)` and `Row::Field(Field::HighContrast)`. The policy store already
   keeps both. Only Settings and the setup wizard may write them
   (`capsule_policy/src/server/handle_set.rs`, `SETTERS`).
2. `app_skeleton` reads both fields with `nonos_policy_client` (`get_u8`, `get_bool`). These go
   through `mk_ipc_call_timeout` with a 200 ms timeout. It reads them at start and then at most
   once a second, the way the keyboard drivers follow `KeyboardLayout` with `Watch`.
3. When either value changes, it calls `theme::store::replace(theme_of(index, high_contrast))` in
   its own process. The store moves its revision.
4. A moved revision forces a full repaint, so the damage path cannot keep drawing old colours.
5. Widgets read `roles()` from that store, so every widget in the app follows.

Only an index and a flag cross processes. Every app already links every scheme, because the
toolkit is linked into it. Nothing new is needed: no new toolkit op, no wire change and no
capability change. Reading policy needs only IPC (`docs/userland/ipc-services.md`), and every
app here has it.

## Why not through the toolkit service

The toolkit service waits in `mk_ipc_recv_from` with no timeout, so it cannot poll on its own.
It would have to poll inside requests, behind an app's 8 ms frame budget, against policy's 200 ms
reply timeout. Every app would still ask it every frame as well. Reading policy directly is one
hop fewer, with no new protocol.

## Light

`b"Light"` is appended to `THEME_LABELS` (`policy_proto/src/theme_labels.rs`), so it becomes
index 8, and its scheme is appended to `SCHEMES`. `every_theme_name_has_a_scheme` fails if one is
added without the other. Settings lists the labels through `enum_table`, so its row shows Light
with no further change.

## Apps on their own loop

| Capsule | Today | Plan |
|---|---|---|
| `capsule_desktop_shell` | own server loop; constants in `render/palette.rs` | reads the same two fields in its loop; colours move to roles during migration |
| `setup_wizard` | own loop, runs before setup is done | keeps the default; no choice exists yet |
| `boot_splash`, `wallpaper` | toolkit only | keep the default |
| `capsule_linux` | `linux::run` | out of scope |

## To retire later, as its own decision

Once no app reads the 5-colour store over the wire, the frame handshake in
`app_skeleton/src/runner/paint_frame.rs` goes, along with `TOOLKIT_OP_THEME_GET` and
`TOOLKIT_OP_THEME_APPLY`. Until then, `theme_get` moves to `mk_ipc_call_timeout`, as every client
that expects a reply must.

## Open

- ❓ Whether the `app_skeleton` frame loop wakes up while an app is idle. If it does not, the
  once-a-second check rides on `on_tick` and `tick_interval_ms`. This must be checked before the
  wiring is built.
- `Watch` covers only u8 fields. `HighContrast` is a bool, so it is either read beside `Watch` with
  `get_bool`, or `Watch` gains a bool form.
- Decided: the Browser (#621), the Text Editor and the Terminal keep their own picker and gain a
  "System" option, the default, that follows this setting ([Migration](migration.md)).
