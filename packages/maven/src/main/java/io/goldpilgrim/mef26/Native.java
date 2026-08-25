// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

package io.goldpilgrim.mef26;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Low-level JNI entry points exported by the MEF-26 native library.
 *
 * <p>A production Maven deployment supplies one matching {@code mef26-native-*} platform
 * artifact. The loader extracts its library from {@code META-INF/native}. The normal
 * {@code java.library.path} lookup remains available only for local development.</p>
 */
final class Native {
    static {
        try {
            load();
        } catch (IOException | UnsatisfiedLinkError exception) {
            UnsatisfiedLinkError failure = new UnsatisfiedLinkError(
                    "MEF-26 could not load a matching JNI library. Add the appropriate "
                            + "io.goldpilgrim:mef26-native-<platform>:0.1.0 runtime artifact.");
            failure.initCause(exception);
            throw failure;
        }
    }

    private Native() {
    }

    private static void load() throws IOException {
        String platform = platform();
        String libraryName = System.mapLibraryName("mef_jni");
        String resource = "/META-INF/native/" + platform + "/" + libraryName;
        try (InputStream input = Native.class.getResourceAsStream(resource)) {
            if (input != null) {
                Path extracted = Files.createTempFile("mef26-", "-" + libraryName);
                try {
                    Files.copy(input, extracted, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    extracted.toFile().deleteOnExit();
                    System.load(extracted.toAbsolutePath().toString());
                    return;
                } catch (UnsatisfiedLinkError exception) {
                    Files.deleteIfExists(extracted);
                    throw exception;
                }
            }
        }
        System.loadLibrary("mef_jni");
    }

    private static String platform() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (os.contains("linux") && (arch.equals("amd64") || arch.equals("x86_64"))) {
            return "linux-x64-gnu";
        }
        if (os.contains("mac") && (arch.equals("amd64") || arch.equals("x86_64"))) {
            return "darwin-x64";
        }
        if (os.contains("mac") && (arch.equals("aarch64") || arch.equals("arm64"))) {
            return "darwin-arm64";
        }
        if (os.contains("win") && (arch.equals("amd64") || arch.equals("x86_64"))) {
            return "win32-x64-msvc";
        }
        throw new UnsatisfiedLinkError("Unsupported MEF-26 JNI platform: " + os + "/" + arch);
    }

    static native int abiVersion();

    static native String protocolId();

    static native int maxCiphertextLen();
}
