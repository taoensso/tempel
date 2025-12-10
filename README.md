<a href="https://www.taoensso.com/clojure" title="More stuff by @ptaoussanis at www.taoensso.com"><img src="https://www.taoensso.com/open-source.png" alt="Taoensso open source" width="340"/></a>  
[**API**][cljdoc] | [**Wiki**][GitHub wiki] | [Slack][] | Latest release: [v1.1.0](../../releases/tag/v1.1.0) (2025-12-10)

[![Clj tests][Clj tests SVG]][Clj tests URL]
[![Graal tests][Graal tests SVG]][Graal tests URL]

# Tempel

### Data security framework for Clojure

**Tempel** is a lightweight encryption *framework* that wraps the JVM's native crypto facilities to provide a **particularly high-level Clojure API** for easily protecting your users' data.

More than another collection of crypto utils, Tempel offers a **coherent and opinionated API for secure data management** that is focused on helping with the [toughest parts](../../wiki/1-Getting-started#challenges) of actually **using encryption in practice**.

Its [tiny API](../../wiki/1-Getting-started#api-overview) and focus on **smart keychains** helps shield you from unnecessary and error-prone complexity, greatly simplifying the most common data security needs.

👉 Tempel is [NOT intended](../../wiki/3-Faq#can-i-decrypt-tempel-data-with-other-tools) for interop with other cryptographic tools/APIs!

## Why Tempel?

- **Easy-to-use, high-level API** focused on [common tasks](../../wiki/2-Examples) like logins, encryption, signing, etc.
- **Reasonable defaults** including choice of algorithms and work factors.
- **Future-proof data formats** with auto-updated algorithms and work factors over time.
- Support for [⧉ symmetric](https://en.wikipedia.org/wiki/Symmetric-key_algorithm), [⧉ asymmetric](https://en.wikipedia.org/wiki/Public-key_cryptography) (public-key), and [⧉ end-to-end](https://en.wikipedia.org/wiki/End-to-end_encryption) (E2EE) encryption.
- Automatic [⧉ scrypt](https://en.wikipedia.org/wiki/Scrypt) and [⧉ pbkdf2](https://en.wikipedia.org/wiki/PBKDF2) support for easy **password-based key stretching**.
- Simple **key management API** for password resets, key rotations, etc.
- Extensive **beginner-oriented** [documentation](#documentation), docstrings, and error messages.
- **Comprehensive test suite** with >60k unit tests.

## Disclaimer

⚠️ **Important**: this software is provided *"as is"* and **without warranty of any kind**. You use it **at your own risk**!

While Tempel has been written and tested with care, the nature of the problem domain inevitably means that it can be **easy to misuse** and **sensitive to bugs**.

Misuse or bugs can be **especially harmful** - potentially leading to [security vulnerabilities](../../wiki/3-FAQ#how-secure-is-tempel) or even [permanent data loss](../../wiki/3-FAQ#is-there-a-risk-of-data-loss)!

Whenever you use cryptographic libraries/frameworks (including Tempel), please **test very carefully** and always **back up important data**!

## Video demo

See for intro and usage:

<a href="https://www.youtube.com/watch?v=sULZVFhR848" target="_blank">
 <img src="https://img.youtube.com/vi/sULZVFhR848/maxresdefault.jpg" alt="Tempel demo video" width="480" border="0" />
</a>

## Quick example

```clojure
(require
  '[taoensso.tempel :as tempel]
  '[taoensso.nippy  :as nippy])

;; Create a new private `KeyChain`:
(def my-keychain! (tempel/keychain))
;; => {:n-sym 1, :n-prv 2, :n-pub 2, :secret? true}

;; Use our `KeyChain` to encrypt some data:
(def my-encrypted-data
  (tempel/encrypt-with-symmetric-key
    (nippy/freeze "My secret data")
    my-keychain!)) ; => Encrypted bytes

;; Get back the original unencrypted data:
(nippy/thaw
  (tempel/decrypt-with-symmetric-key
    my-encrypted-data my-keychain!)) ; => "My secret data"

;; It's safe to store encrypted `KeyChain`s:
(def my-encrypted-keychain
  (tempel/encrypt-keychain my-keychain!
    {:password "My password"})) ; => Encrypted bytes

;; Get back the original unencrypted `KeyChain`:
(= my-keychain!
  (tempel/decrypt-keychain my-encrypted-keychain
    {:password "My password"})) ; => true

;; `KeyChain`s also support:
;;   - `encrypt-with-1-keypair`
;;   - `encrypt-with-2-keypairs`
;;   - `sign`

;; See docstrings and/or wiki for more info!
```

## Documentation

- [Wiki][GitHub wiki] (getting started, usage, etc.)
- API reference via [cljdoc][cljdoc]
- Support via [Slack][] or [GitHub issues][]

## Security

See [here](../../security) for **security advisories** and/or to **report possible security vulnerabilities**.

## Funding

You can [help support][sponsor] continued work on this project and [others][my work], thank you!! 🙏

## License

Copyright &copy; 2023-2025 [Peter Taoussanis][].  
Licensed under [EPL 1.0](LICENSE.txt) (same as Clojure).

<!-- Common -->

[GitHub releases]: ../../releases
[GitHub issues]:   ../../issues
[GitHub wiki]:     ../../wiki
[Slack]:   https://www.taoensso.com/tempel/slack

[Peter Taoussanis]: https://www.taoensso.com
[sponsor]:          https://www.taoensso.com/sponsor
[my work]:          https://www.taoensso.com/clojure-libraries

<!-- Project -->

[cljdoc]: https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel

[Clojars SVG]: https://img.shields.io/clojars/v/com.taoensso/tempel.svg
[Clojars URL]: https://clojars.org/com.taoensso/tempel

[Clj tests SVG]:  https://github.com/taoensso/tempel/actions/workflows/clj-tests.yml/badge.svg
[Clj tests URL]:  https://github.com/taoensso/tempel/actions/workflows/clj-tests.yml
[Graal tests SVG]: https://github.com/taoensso/tempel/actions/workflows/graal-tests.yml/badge.svg
[Graal tests URL]: https://github.com/taoensso/tempel/actions/workflows/graal-tests.yml
