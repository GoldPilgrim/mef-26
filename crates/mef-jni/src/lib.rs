// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! JNI metadata binding for the MEF-26 Maven package.

use jni::{
    EnvUnowned,
    errors::ThrowRuntimeExAndDefault,
    objects::JClass,
    sys::{jint, jstring},
};

/// JNI entry point for `io.goldpilgrim.mef26.Native.abiVersion`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_goldpilgrim_mef26_Native_abiVersion(
    _environment: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jint {
    mef_26::ABI_VERSION as jint
}

/// JNI entry point for `io.goldpilgrim.mef26.Native.protocolId`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_goldpilgrim_mef26_Native_protocolId(
    mut environment: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jstring {
    environment
        .with_env(|env| env.new_string(mef_26::PROTOCOL_ID).map(|value| value.into_raw()))
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// JNI entry point for `io.goldpilgrim.mef26.Native.maxCiphertextLen`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_goldpilgrim_mef26_Native_maxCiphertextLen(
    _environment: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jint {
    mef_26::MAX_CIPHERTEXT_LEN as jint
}
