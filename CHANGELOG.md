This project uses [**Break Versioning**](https://www.taoensso.com/break-versioning).

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
