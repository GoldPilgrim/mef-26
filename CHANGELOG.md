# Changelog

All notable compatibility and security-relevant changes are recorded here.

## 0.1.1

This release extends the MEF-26 version-1 protocol family without changing the existing classical wire profile.

### Added

- Added `AeadSuite::Aes256GcmSiv`, a selectable AES-256-GCM-SIV payload protection suite with strict 12-byte nonce validation and authenticated associated data.
- Added the feature-gated native Rust `hybrid` profile combining the authenticated X25519 prekey path with ML-KEM-768 (FIPS 203) encapsulation.
- Added canonical hybrid bundle, initiator-message and responder-message encodings with signed-prekey and transcript binding.
- Added ratchet integration coverage for AES-256-GCM-SIV and persistence suite restoration.

### Changed

- Ratchet initialization now supports an explicit authenticated AEAD suite while retaining the existing XChaCha20-Poly1305 default.
- Encrypted ratchet persistence is version 2 and records the selected payload suite. Version-1 XChaCha20-Poly1305 snapshots remain readable.
- Updated Rust, C, Node.js and JVM release metadata to `0.1.1`.
- Tightened documentation around the hybrid profile: it is a native ML-KEM integration and not a formal PQXDH security proof.

### Compatibility and security notes

The classical handshake and existing version-1 frame and envelope formats remain available. Applications must negotiate the payload suite and hybrid profile through an authenticated, downgrade-resistant policy. An independent cryptographic audit remains required before production deployment.

## 0.1.0

This experimental release establishes the version-1 MEF-26 wire formats and introduces the classical authenticated prekey handshake, bounded ratchet, encrypted state persistence, opaque delivery envelopes and metadata-only foreign-language ABIs.

The `pq` feature is primitive-only and is not a post-quantum handshake. Stateful C, Node.js and JVM APIs are intentionally not part of this release.
