<a href="https://www.taoensso.com/clojure" title="More stuff by @ptaoussanis at www.taoensso.com"><img src="https://www.taoensso.com/open-source.png" alt="Taoensso open source" width="340"/></a>  
[**Documentation**](#documentation) | [Latest releases](#latest-releases) | [Get support][GitHub issues]

# Tempel

### Data security framework for Clojure

**Tempel** is a lightweight encryption framework that wraps the JVM's native crypto facilities to provide a **high-level Clojure API** that is: idiomatic, simple, and **easy-to-use** even for non-experts.

It incorporates **best practices and reasonable defaults** to help simplify many common data security needs.

## Latest release/s

- `2023-11-13` `1.0.0-alpha1`: [release notes](../../releases/tag/v1.0.0-alpha1)

[![Main tests][Main tests SVG]][Main tests URL]
[![Graal tests][Graal tests SVG]][Graal tests URL]

See [here][GitHub releases] for earlier releases.

## Why Tempel?

- **Easy-to-use, high-level API** focused on [common tasks](../../wiki/2-Examples) like logins, encryption, signing, etc.
- **Reasonable defaults** including choice of algorithms and work factors
- **Future-proof data formats** with auto-updated algorithms and work factors over time
- Support for [⧉ symmetric](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) and [⧉ asymmetric](https://en.wikipedia.org/wiki/Public-key_cryptography) (public-key) encryption
- Automatic [⧉ scrypt](https://en.wikipedia.org/wiki/Scrypt) and [⧉ pbkdf2](https://en.wikipedia.org/wiki/PBKDF2) support for easy **password-based key stretching**
- Simple **key management API** for password resets, key rotations, etc.
- Beginner-oriented docstrings and [documentation](#documentation)

Note that Tempel is [not intended](../../wiki/3-Faq#can-i-decrypt-tempel-data-with-other-tools) for interop with other cryptographic tools/APIs.

## Disclaimer

**Important**: while Tempel has been written and tested with care, the nature of the problem domain inevitably means that bugs and/or misuse can be **especially harmful and/or easy to make**.

Bugs and/or misuse could lead to [security vulnerabilities](../../wiki/3-FAQ#how-secure-is-tempel) or even [permanent data loss](../../wiki/3-FAQ#is-there-a-risk-of-data-loss).

Please be **very careful** evaluating Tempel and/or other cryptographic libraries/frameworks before use, especially new libraries/frameworks like Tempel!

## Documentation

- [Full documentation][GitHub wiki] (**getting started** and more)
- Auto-generated API reference: [Codox][Codox docs], [clj-doc][clj-doc docs]

## Security advisories

No advisories as of last README update. If any security vulnerabilities are discovered, they will be listed here along with an appropriate CVE.

## Security reports

To report a possible security vulnerability, **please email me** at `my first name at taoensso.com`. For particularly sensitive content, you may encrypt your message with my [public PGP/GPG key](https://www.taoensso.com/pgp). Thank you! - Peter Taoussanis

## Funding

You can [help support][sponsor] continued work on this project, thank you!! 🙏

## License

Copyright &copy; 2023 [Peter Taoussanis][].  
Licensed under [EPL 1.0](LICENSE.txt) (same as Clojure).

<!-- Common -->

[GitHub releases]: ../../releases
[GitHub issues]:   ../../issues
[GitHub wiki]:     ../../wiki

[Peter Taoussanis]: https://www.taoensso.com
[sponsor]:          https://www.taoensso.com/sponsor

<!-- Project -->

[Codox docs]:   https://taoensso.github.io/tempel/
[clj-doc docs]: https://cljdoc.org/d/com.taoensso/tempel/

[Clojars SVG]: https://img.shields.io/clojars/v/com.taoensso/tempel.svg
[Clojars URL]: https://clojars.org/com.taoensso/tempel

[Main tests SVG]:  https://github.com/taoensso/tempel/actions/workflows/main-tests.yml/badge.svg
[Main tests URL]:  https://github.com/taoensso/tempel/actions/workflows/main-tests.yml
[Graal tests SVG]: https://github.com/taoensso/tempel/actions/workflows/graal-tests.yml/badge.svg
[Graal tests URL]: https://github.com/taoensso/tempel/actions/workflows/graal-tests.yml