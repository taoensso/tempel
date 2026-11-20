This project uses [**Break Versioning**](https://www.taoensso.com/break-versioning).

---

# `v1.2.0-RC1` (2026-11-21)

- **Dependency**: [on Clojars](https://clojars.org/com.taoensso/tempel/versions/1.2.0-RC1)
- **Versioning**: [Break Versioning](https://www.taoensso.com/break-versioning)

This is a **release candidate** for v1.2, with security fixes, new key algorithms, and public-key encryption for keychains. It needs Java 17+.

Please test carefully with copies of your existing data before upgrading production systems, and report any unexpected issues. Thank you! 🙏

\- [Peter Taoussanis](https://www.taoensso.com)

**Most users on default settings need no changes**. Data written with default settings is readable by v1.1 and vice versa, so rolling back won't strand data unless you use the new algorithms, `:key-pub`, or RSA keys with a non-default JCA provider (see below).

Action is needed only if you:

- Run Java < 17: upgrade your JVM, or stay on v1.1.
- Use `:pbkdf-nwf :ref-5000-msecs`: a typo gave this only ~10 msecs of work. It now takes ~5 secs as intended (~500x slower), so check your latency budget and re-encrypt existing data.
- Have a private `:backup-key` in `*config*`: this let a wrong password pass `keychain-decrypt`. Backup keys must now be given per call to decrypt.
- Use RSA keys with Bouncy Castle (or similar) as your preferred JCA provider: upgrade readers before writers.
- Are affected by a breaking change below (all rare).

**Recommended** when decrypting untrusted data: enable the new opt-in `:require-hmac?` and `:pbkdf-nwf-max` options (see `*config*` docstring).

## BREAKING

- [mod] Require Java 17+, add Ed25519 [[147641f](https://github.com/taoensso/tempel/commit/147641ff663edd8f10ab62da8af3ccf2f2faa04a)]
- [mod] Require explicit backup-key recovery [[4c5c025](https://github.com/taoensso/tempel/commit/4c5c0250070f20ccac043eef4c49c56e00775c34)]
- [mod] Require HMAC for keychains and CBC [[14745af](https://github.com/taoensso/tempel/commit/14745af89aa45c231ef70e11854b440bca63c76a)]
- [mod] `signed`: reject MD5 and SHA-1 [[0437fc1](https://github.com/taoensso/tempel/commit/0437fc18a52a2bcf597610b5c6411f51c302e073)]
- [mod] Reject zero-round SHA-512 PBKDF [[9f0bcb3](https://github.com/taoensso/tempel/commit/9f0bcb3328fa154af48d41883807eec602f86461)]
- [mod] `:ba-akm`: require a byte array [[fc15cf2](https://github.com/taoensso/tempel/commit/fc15cf2eec31304d77ffe5927ea6cd940f8032fb)]

## Fixes

- [sec] Check envelope field sizes before allocating [[2321f80](https://github.com/taoensso/tempel/commit/2321f80c8e6a2e914edf0121190be246427dfd19)]
- [sec] `:pbkdf-nwf :ref-5000-msecs`: fix wrong work factor [[1013203](https://github.com/taoensso/tempel/commit/1013203c89ef8460ba0c55f9fdc89c286448edb4)]
- [sec] `keypair-creator`: isolate buffer from custom RNGs [[f3c50ff](https://github.com/taoensso/tempel/commit/f3c50ff27cd0d11b68f7004bd498dd544627856a)]
- [sec] X25519: reject all-zero shared secrets [[18331c6](https://github.com/taoensso/tempel/commit/18331c686682b53d16775fc1ab593f343c71764e)]
- [fix] `keychain-add-*`: preserve added keys [[fdd519d](https://github.com/taoensso/tempel/commit/fdd519debf4b2d86b6dcba64a6aa3ecd742ce1bb)]
- [fix] `decrypt-with-2-keypairs`: fix key lookup [[bc4fabc](https://github.com/taoensso/tempel/commit/bc4fabcfa03a76d031f659417c01e27b895d7e59)]
- [fix] RSA-OAEP: fix provider-dependent params [[212e7ae](https://github.com/taoensso/tempel/commit/212e7aef05a0391e70aa390330fbb3591cea79ba)]
- [fix] `keychain-decrypt`: don't return nil for non-key errors [[85f0237](https://github.com/taoensso/tempel/commit/85f0237340d9f911e3b433257a5b8da9c1f58174)]
- [fix] Backup keys: fix recursion with global `:backup-key` [[0de3910](https://github.com/taoensso/tempel/commit/0de3910fe6fddd0f8105473de1139efafcfa493c)]
- [fix] `KeyChain`s: don't share byte[]s with callers [[8343902](https://github.com/taoensso/tempel/commit/834390297beb2d39b9bd5306d57310d598b9fe35)]
- [fix] `ChainKey`s: don't share symmetric byte[]s [[11a110e](https://github.com/taoensso/tempel/commit/11a110ece75e2ca6fde5a5ed0ee9cbddb3189e81)]
- [fix] Reject `:random` as direct encryption key [[97f3cc1](https://github.com/taoensso/tempel/commit/97f3cc1e66b81c9d0bf53d8b5b6d4e6fc6e49402)]
- [fix] `sign`: support SHA-512 ECDSA envelopes [[b6d9069](https://github.com/taoensso/tempel/commit/b6d906955ba1289dd938ecbe047de85933120ea1)]
- [sec] Misc defensive hardening [[5e2f0f9](https://github.com/taoensso/tempel/commit/5e2f0f9384f98c2ff9a0d49b716296dfaa15723b)]
- [fix] `KeyChain`s: clear error for out-of-range priorities [[7037dd4](https://github.com/taoensso/tempel/commit/7037dd49514d6b2c5d0e98ad6ed7ef1be42c425e)]
- [fix] Fix login system examples [[27404ae](https://github.com/taoensso/tempel/commit/27404ae655938d73f906645d6790a4e401f0d091)]

## New

- [new] Add new key algo: `:x25519` [[7b29928](https://github.com/taoensso/tempel/commit/7b299284e1b275f230b914b4c61b55cea3f26e71)]
- [new] Add new public-key encryption: `:x25519` [[330d557](https://github.com/taoensso/tempel/commit/330d5572585a9518dee8f95b3646810958290740)]
- [new] Add new key algo: `:ed25519` [[147641f](https://github.com/taoensso/tempel/commit/147641ff663edd8f10ab62da8af3ccf2f2faa04a)]
- [new] [#12](https://github.com/taoensso/tempel/issues/12) `keychain-encrypt`: support public keys [[405c999](https://github.com/taoensso/tempel/commit/405c99984a23fedd5b403513535f93a573c3e365)]
- [new] Add `:require-hmac?` decryption option [[7c6fff1](https://github.com/taoensso/tempel/commit/7c6fff14b0752824582fccf0e5b28b0435885e20)]
- [new] Add `:pbkdf-nwf-max` decryption option [[0b55255](https://github.com/taoensso/tempel/commit/0b55255df2a0db6897489471e63d85a1aefb8079)]
- [new] `sign`: add RSA-PSS signature algorithms [[3f6669e](https://github.com/taoensso/tempel/commit/3f6669e5ee36a875accd435e2c18c405f2dd145f)]
- [doc] Backup recovery caveats, forward secrecy, AES-256 note [[346d124](https://github.com/taoensso/tempel/commit/346d124f990ef2e51ffa7518d2a629c09f61efde)]
- [doc] Wiki: cover password settings and sharing [[dcd91db](https://github.com/taoensso/tempel/commit/dcd91dbd2f8debd4d20dc1903ab0f8e9e59d96b8)]

---

# `v1.1.0` (2025-12-10)

- **Dependency**: [on Clojars](https://clojars.org/com.taoensso/tempel/versions/1.1.0)
- **Versioning**: [Break Versioning](https://www.taoensso.com/break-versioning)

This is a **minor maintenance release** that should be a safe upgrade for folks on `v1.0.0`.

It introduces [new utils](https://github.com/taoensso/tempel/issues/15) to make it easier to de/serialize public parts of `KeyChain`s.

---

# `v1.0.0` (2025-11-05)

- **Dependency**: [on Clojars](https://clojars.org/com.taoensso/tempel/versions/1.0.0)
- **Versioning**: [Break Versioning](https://www.taoensso.com/break-versioning)

At long last- this is the first **stable v1** release of Tempel! 🎉

It is functionally identical to (and bidirectionally data compatible with) v1.0.0-RC1 (2024-02-26), but now marked as "production ready".

## Disclaimer

⚠️ **Important**: this software is provided *"as is"* and **without warranty of any kind**. You use it **at your own risk**!

While Tempel has been written and tested with care, the nature of the problem domain inevitably means that it can be **easy to misuse** and **sensitive to bugs**.

Misuse or bugs can be **especially harmful** - potentially leading to [security vulnerabilities](../../wiki/3-FAQ#how-secure-is-tempel) or even [permanent data loss](../../wiki/3-FAQ#is-there-a-risk-of-data-loss)!

Whenever you use cryptographic libraries/frameworks (including Tempel), please **test very carefully** and always **back up important data**!

Please report any unexpected issues! Possible security issues may be responsibly reported [here](https://github.com/taoensso/tempel/security), thank you! 🙏

## Since `v1.0.0-RC1` (2024-02-26)

- Use [contextual Truss exceptions](https://github.com/taoensso/truss#contextual-exceptions) for all errors
- Documentation and example improvements
- Update dependencies

---

# `v1.0.0-RC1` (2024-02-26)

> **Dep/s**: Tempel is [on Clojars](https://clojars.org/com.taoensso/tempel/versions/1.0.0-RC1).  
> **Versioning**: Tempel uses [Break Versioning](https://www.taoensso.com/break-versioning).

⚠️ This release is intended for **development/testing** with **ephemeral or low-value data**. Tempel `v1.0` final is expected around [May 2024](https://www.taoensso.com/roadmap).

Please report any problems and let me know if anything is unclear, inconvenient, etc. Thank you! 🙏

## New since `v1.0.0-beta1`

* 9001f1b [new] Add `encrypt-keychain`, `decrypt-keychain` aliases
* Misc documentation improvements, incl. new [demo video](https://www.youtube.com/watch?v=sULZVFhR848)

---

# `v1.0.0-beta1` (2024-02-01)

> 📦 [Available on Clojars](https://clojars.org/com.taoensso/tempel/versions/1.0.0-beta1), this project uses [Break Versioning](https://www.taoensso.com/break-versioning).

⚠️ **Please don't use this in production yet**, this release is intended for early testers and for those that would like to give feedback. Please report any unexpected problems and let me know if anything is unclear, inconvenient, etc. Now's the ideal time to get changes in. Thank you! 🙏

## Changes since `v1.0.0-alpha1`

* 1931c7d [mod] Rename {:return :as-map} -> {:return :map}

## New since `v1.0.0-alpha1`

* 1e1fdbd [new] [#1] [#2] Add ChaCha20-Poly1305 AEAD cipher (@iarenaza)

---

# `v1.0.0-alpha1` (2023-11-13)

> 📦 [Available on Clojars](https://clojars.org/com.taoensso/tempel/versions/1.0.0-alpha1), this project uses [Break Versioning](https://www.taoensso.com/break-versioning).

This is Tempel's first public pre-release.

⚠️ **Please don't use this in production yet**, this release is intended for early testers and for those that would like to give feedback. Please report any unexpected problems and let me know if anything is unclear, inconvenient, etc. Now's the ideal time to get changes in. Thank you! 🙏
