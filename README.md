# MEF-26

MEF-26 is an AGPL-3.0-or-later Rust framework core for **1:1 end-to-end encrypted messaging**. It provides an authenticated asynchronous X25519 prekey handshake, a bounded Double Ratchet state machine, canonical authenticated frames, encrypted ratchet persistence, and opaque delivery envelopes. It is not a complete messenger product or a hosted delivery service.

## Scope

| Component | Responsibility |
|---|---|
| `handshake` | Classical X25519 asynchronous prekey profile with Ed25519 identity binding, signed prekeys, optional one-time prekeys, canonical initiator messages, and transcript-bound session material. |
| `ratchet` | One-time message keys, bounded out-of-order delivery, DH recovery steps, and versioned encrypted snapshot/restore with rollback-floor enforcement. |
| `frame` | Versioned canonical inner-message encoding with authenticated session, ratchet and counter headers. |
| `envelope` | X25519-sealed mailbox envelope, expiry, authenticated padding removal, and bounded recipient replay cache. |
| `crypto` | Typed wrappers over BLAKE3, HKDF-SHA-256, X25519, Ed25519, AES-256-GCM, ChaCha20-Poly1305 and XChaCha20-Poly1305. |
| `pq` | Optional ML-KEM-768 primitive adapter. It is **not** composed into this handshake and does not claim PQXDH security. |

The C, Node.js and JVM packages currently expose ABI metadata only. They are not stateful cryptographic bindings; an opaque-handle ABI requires its own review.

## Secure integration sequence

| Step | Required action |
|---|---|
| 1 | Publish a verified `ResponderPrekeyBundle` through an authenticated key directory. Rotate signed prekeys and replenish one-time prekeys according to service policy. |
| 2 | Call `handshake::initiate` only after verifying the remote identity through the application’s trust UX. Deliver the canonical `InitiatorHandshake` to the responder. |
| 3 | Call `handshake::accept`, then initialize each endpoint using `RatchetState::from_authenticated_handshake`. The raw-byte-secret constructor is intentionally unavailable. |
| 4 | Store `RatchetState::seal_state` output and its monotonic rollback floor atomically with each outbound ciphertext or accepted inbound message. Use a platform-secure `StateSealKey` and account/device/session-specific context. |
| 5 | Use `OuterEnvelope::open_inner_once` with a persisted, bounded `ReplayCache`. This authenticates the envelope, removes checked zero padding, and rejects duplicate transport IDs. |
| 6 | Protect local identity/prekey/persistence keys with platform secure storage and provide explicit identity-change verification UX. |

`OuterEnvelope` conceals the inner payload from a delivery gateway. It does **not** conceal IP address, traffic timing, recipient routing, contact graph, or endpoint compromise. Those properties require a separate relay deployment, operational policy and client UX.

## Build and test

Rust **1.89** or later is required.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release --all-features
```

## Language bindings

| Target | Current contract |
|---|---|
| C | Versioned metadata ABI. Build with `cargo build -p mef-ffi --release`. |
| Node.js | Metadata ABI. `@goldpilgrim/mef26` resolves one optional `@goldpilgrim/mef26-<platform>` package containing the matching prebuilt `.node` artifact. |
| JVM | Metadata ABI. Add `io.goldpilgrim:mef26-native-<platform>:0.1.0` at runtime; it contributes the matching `mef_jni` library as a classpath resource. |

## Security status

MEF-26 has parser, state-transition and regression coverage, but **an independent cryptographic audit is required before production deployment**. The classical handshake profile is specified by this implementation; post-quantum composition, multi-device policy, group messaging and anonymity transport are explicitly outside the current security claim.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

Copyright (C) 2026 [GoldPilgrim](https://github.com/GoldPilgrim).

Licensed under the GNU Affero General Public License, version 3 or later. See [LICENSE](LICENSE).
