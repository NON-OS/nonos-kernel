# capsule_hello

## Role

`capsule_hello` is the minimal window app on `nonos_app_skeleton`: a 360 by
220 window titled "Hello NONOS" that draws four labels from the toolkit's shared
widgets, in the colours of the theme chosen in Settings, and closes on Esc. It is the reference app for the docs quickstart guide, and the smallest
example of the skeleton's window path. How an app capsule is structured is in
[docs/handbook/desktop/app-model.md](../../docs/handbook/desktop/app-model.md).

```text
hello app -> nonos_app_skeleton -> compositor -> display driver
```

## Microkernel contract

- `CAPSULE_REQUIRED_CAPS := 0x1819`: CoreExec, IPC, Memory,
  GraphicsDisplayQuery and GraphicsSurfaceCreate. It requests no filesystem,
  network, hardware broker, crypto, admin, DMA, PIO, IRQ or debug capability.
- Service `service:4810:app.hello`, reply `reply:4811:endpoint.app.hello.reply`.
- The skeleton registers the window over IPC, receives key-down events and
  presents the painted buffer through the compositor.
- The kernel mirror is `src/userspace/capsule_hello`. The feature
  `nonos-capsule-hello` is in `microkernel-full-gui`, where init spawns it with
  the other apps.

## Persistence

No persistent state. The window rebuilds everything in memory on spawn.
