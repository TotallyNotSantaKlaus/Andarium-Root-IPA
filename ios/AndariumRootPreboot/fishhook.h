// SPDX-License-Identifier: BSD-3-Clause
// Minimal 64-bit Darwin Mach-O symbol rebinder (derived from Facebook fishhook).

#ifndef ANDARIUM_FISHHOOK_H
#define ANDARIUM_FISHHOOK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ar_rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

int ar_rebind_symbols(struct ar_rebinding rebindings[], size_t rebindings_nel);

#ifdef __cplusplus
}
#endif

#endif // ANDARIUM_FISHHOOK_H
