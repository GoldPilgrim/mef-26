// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

package io.goldpilgrim.mef26;

/**
 * Public metadata facade for the MEF-26 native Maven package.
 *
 * <p>The package is licensed under AGPL-3.0-or-later. Deployments must provide the
 * corresponding native library for their operating system and architecture.</p>
 */
public final class Mef26 {
    private Mef26() {
    }

    /**
     * Returns the additive native binding ABI version.
     *
     * @return the ABI version implemented by the loaded native library
     */
    public static int abiVersion() {
        return Native.abiVersion();
    }

    /**
     * Returns the protocol identifier bound into MEF-26 cryptographic labels.
     *
     * @return the constant protocol identifier
     */
    public static String protocolId() {
        return Native.protocolId();
    }

    /**
     * Returns the maximum accepted inner ciphertext body length.
     *
     * @return the maximum ciphertext length in bytes
     */
    public static int maxCiphertextLen() {
        return Native.maxCiphertextLen();
    }
}
