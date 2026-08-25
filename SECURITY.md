# Security Policy

## Reporting a vulnerability

Do **not** publish suspected vulnerabilities in public issues. Send a concise report, reproduction details, affected version and suggested impact assessment to the repository owner through the private contact channel listed on the [GoldPilgrim GitHub profile](https://github.com/GoldPilgrim).

A report should include enough information to reproduce the issue without exposing private user data or production keys. The maintainer will acknowledge a valid report, coordinate a fix, assign an affected-version range and publish remediation notes before public disclosure where practical.

## Supported versions

| Version line | Security status |
|---|---|
| `0.1.x` | Experimental. No production security guarantee; update to the newest release before reporting an issue. |

## Scope boundary

MEF-26 is a cryptographic framework core. Delivery infrastructure, identity-directory operation, client secure storage, multi-device policy, traffic-analysis resistance and post-quantum handshake composition are outside the current audited claim. An independent cryptographic audit remains required before production deployment.
