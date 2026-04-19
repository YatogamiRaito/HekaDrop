# Security Policy

> 🇹🇷 Türkçe sürüm: [`SECURITY.md`](SECURITY.md)

## Supported versions

Only the latest minor release receives security fixes. The 0.x line is
early-access so API stability is not guaranteed — behavioral changes
outside security fixes may ship with a minor version bump.

| Version | Support              |
|---------|----------------------|
| 0.4.x   | ✅ active            |
| < 0.4   | ❌ no more updates   |

## Responsible disclosure

HekaDrop speaks a network protocol, so vulnerabilities can have serious
impact. Please reach out **before** filing a public issue:

- **GitHub Private Vulnerability Reporting** (preferred):
  https://github.com/YatogamiRaito/HekaDrop/security/advisories/new
- **Email:** destek@sourvice.com — use the subject `[HekaDrop security]`

Helpful info to include:

- Affected version(s) and operating system
- Step-by-step reproduction (PoC, logs, screenshots, etc.)
- Your impact assessment and estimated severity

We commit to replying within **72 hours**. For critical issues we'll
prepare a fix and coordinate the public disclosure with you. We're happy
to assist with CVE requests.

## Scope

HekaDrop's core protocol is reverse-engineered from Google Quick Share
(Nearby Share). We consider reports in the following classes:

- ✅ Rust memory safety (UB, UAF, double-free in unsafe blocks)
- ✅ Crypto: UKEY2 handshake, AES-CBC + HMAC, PIN verification, replay protection
- ✅ Network: RCE over mDNS/TCP, DoS, memory exhaustion
- ✅ Local: filesystem path traversal, privilege escalation
- ✅ Third-party dependency vulnerabilities (`cargo audit`)

Out of scope:

- Attacks requiring root/admin on the victim device
- Social engineering (voluntarily sharing the PIN, etc.)
- Security issues in the Android counterpart (report to Google)

## Credit

With the reporter's permission, we credit contributions in `CHANGELOG.md`
and release notes.
