// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

import { copyFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const [platformDirectory, artifactPath] = process.argv.slice(2);
if (!platformDirectory || !artifactPath) {
  throw new Error('Usage: node scripts/package-native.mjs <platform-directory> <native-artifact-path>');
}

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const source = resolve(artifactPath);
const destination = resolve(packageRoot, 'platforms', platformDirectory, 'mef26.node');
if (!existsSync(source)) {
  throw new Error(`Native artifact does not exist: ${source}`);
}
copyFileSync(source, destination);
