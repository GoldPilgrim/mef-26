/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
 * This file is part of MEF-26.
 */

#ifndef MEF26_H
#define MEF26_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the additive ABI version implemented by this library.
 * This function has no failure mode.
 */
uint32_t mef26_abi_version(void);

/**
 * Returns a borrowed, process-static, NUL-terminated protocol identifier.
 * The returned pointer is never NULL and must not be freed.
 */
const char *mef26_protocol_id(void);

/**
 * Returns the maximum accepted MEF-26 inner ciphertext body length in bytes.
 * This function has no failure mode.
 */
size_t mef26_max_ciphertext_len(void);

#ifdef __cplusplus
}
#endif

#endif /* MEF26_H */
