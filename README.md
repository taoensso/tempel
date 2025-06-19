<a href="https://www.taoensso.com/clojure" title="More stuff by @ptaoussanis at www.taoensso.com"><img src="https://www.taoensso.com/open-source.png" alt="Taoensso open source" width="340"/></a>  
[**API**][cljdoc] | [**Wiki**][GitHub wiki] | [Latest releases](#latest-releases) | [Slack channel][]

# Tempel

### Data security framework for Clojure

**Tempel** is a lightweight encryption *framework* that wraps the JVM's native crypto facilities to provide a **particularly high-level Clojure API** for easily protecting your users' data.

More than another collection of crypto utils, Tempel offers a **coherent and opinionated API for secure data management** that is focused on helping with the [toughest parts](../../wiki/1-Getting-started#challenges) of actually **using encryption in practice**.

Its [tiny API](../../wiki/1-Getting-started#api-overview) and focus on **smart keychains** helps shield you from unnecessary and error-prone complexity, greatly simplifying the most common data security needs.

⚠️ Tempel is [NOT intended](../../wiki/3-Faq#can-i-decrypt-tempel-data-with-other-tools) for interop with other cryptographic tools/APIs!

## Latest release/s

- `2024-02-26` `v1.0.0-RC1`: [release info](../../releases/tag/v1.0.0-RC1)

[![Main tests][Main tests SVG]][Main tests URL]
[![Graal tests][Graal tests SVG]][Graal tests URL]

See [here][GitHub releases] for earlier releases.

## Why Tempel?

- **Easy-to-use, high-level API** focused on [common tasks](../../wiki/2-Examples) like logins, encryption, signing, etc.
- **Reasonable defaults** including choice of algorithms and work factors.
- **Future-proof data formats** with auto-updated algorithms and work factors over time.
- Support for [⧉ symmetric](https://en.wikipedia.org/wiki/Symmetric-key_algorithm), [⧉ asymmetric](https://en.wikipedia.org/wiki/Public-key_cryptography) (public-key), and [⧉ end-to-end](https://en.wikipedia.org/wiki/End-to-end_encryption) (E2EE) encryption.
- Automatic [⧉ scrypt](https://en.wikipedia.org/wiki/Scrypt) and [⧉ pbkdf2](https://en.wikipedia.org/wiki/PBKDF2) support for easy **password-based key stretching**.
- Simple **key management API** for password resets, key rotations, etc.
- Extensive **beginner-oriented** [documentation](#documentation), docstrings, and error messages.
- **Comprehensive test suite** with >60k unit tests.

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
- Support via [Slack channel][] or [GitHub issues][]

## Roadmap

Tempel has a **fixed scope**, and is **fully complete**. I'm happy with its design and implementation, and believe it meets all its objectives in its current form. I'm not anticipating significant changes.

Still, given the sensitivity of the problem domain, I plan to approach Tempel's official stable release as a phased rollout to allow time for feedback before locking things down:

| Phase | Date    | Release      | Appropriate for                           |
| :---: | :------ | :----------- | :---------------------------------------- |
|  👉   | 2024-02 | `v1.0-RC1`   | Staging, with ephemeral or low-value data |
|       | 2025-05 | `v1.0` final | Production, with real data                |

`v1.0` final will be considered "**done**"- the library is expected to need+see only minimal maintance from that point.

## Disclaimer

**Important**: while Tempel has been written and tested with care, the nature of the problem domain inevitably means that bugs and/or misuse can be **especially harmful and/or easy to make**.

Bugs and/or misuse could lead to [security vulnerabilities](../../wiki/3-FAQ#how-secure-is-tempel) or even [permanent data loss](../../wiki/3-FAQ#is-there-a-risk-of-data-loss).

Please be **very careful** evaluating Tempel and/or other cryptographic libraries/frameworks before use, especially new libraries/frameworks like Tempel!

## Security

See [here](../../security) for **security advisories** and/or to **report security vulnerabilities**.

## Funding

You can [help support][sponsor] continued work on this project and [others][my work], thank you!! 🙏

## License

Copyright &copy; 2023-2025 [Peter Taoussanis][].  
Licensed under [EPL 1.0](LICENSE.txt) (same as Clojure).

<!-- Common -->

[GitHub releases]: ../../releases
[GitHub issues]:   ../../issues
[GitHub wiki]:     ../../wiki
[Slack channel]:   https://www.taoensso.com/tempel/slack

[Peter Taoussanis]: https://www.taoensso.com
[sponsor]:          https://www.taoensso.com/sponsor
[my work]:          https://www.taoensso.com/clojure-libraries

<!-- Project -->

[cljdoc]: https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel

[Clojars SVG]: https://img.shields.io/clojars/v/com.taoensso/tempel.svg
[Clojars URL]: https://clojars.org/com.taoensso/tempel

[Main tests SVG]:  https://github.com/taoensso/tempel/actions/workflows/main-tests.yml/badge.svg
[Main tests URL]:  https://github.com/taoensso/tempel/actions/workflows/main-tests.yml
[Graal tests SVG]: https://github.com/taoensso/tempel/actions/workflows/graal-tests.yml/badge.svg
[Graal tests URL]: https://github.com/taoensso/tempel/actions/workflows/graal-tests.yml
