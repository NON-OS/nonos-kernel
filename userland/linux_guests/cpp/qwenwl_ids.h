/* The object ids qwenchat's window allocates; wl_display is 1. */
#pragma once
#include <cstdint>
enum : uint32_t { REG = 2, SYNC, COMP, SHM, XDG, SEAT, SURF, XSURF, TOP, POOL, BUF, KBD, POOL2, BUF2, PTR };
/* A resize takes the other pool and buffer pair, POOL2 and BUF2 or back. */
