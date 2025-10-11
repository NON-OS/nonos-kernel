// PQClean expects: void randombytes(uint8_t *buf, size_t n);
// We route to the kernel’s RNG via a Rust-exported symbol.

#include <stdint.h>
#include <stddef.h>

extern void nonos_randombytes(uint8_t *buf, size_t n);

void randombytes(uint8_t *buf, size_t n) {
    nonos_randombytes(buf, n);
}
