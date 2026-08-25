// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

'use strict';

const targetPackages = {
  'darwin-arm64': '@goldpilgrim/mef26-darwin-arm64',
  'darwin-x64': '@goldpilgrim/mef26-darwin-x64',
  'linux-x64': '@goldpilgrim/mef26-linux-x64-gnu',
  'win32-x64': '@goldpilgrim/mef26-win32-x64-msvc',
};

const target = `${process.platform}-${process.arch}`;
const packageName = targetPackages[target];

if (!packageName) {
  throw new Error(
    `MEF-26 has no published N-API package for ${target}. Supported targets: ${Object.keys(targetPackages).join(', ')}.`,
  );
}

try {
  module.exports = require(packageName);
} catch (error) {
  throw new Error(
    `MEF-26 could not load ${packageName}. Install the matching optional platform package or use a supported release artifact.`,
    { cause: error },
  );
}
