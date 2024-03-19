# Can I decrypt Tempel data with other tools?

**No**, Tempel is **intentionally not designed** for interop with other general-purpose cryptographic tools or portability between platforms/languages/etc.

Tempel presumes that you'll do both encryption and decryption *using Tempel*, with **Clojure on the JVM**.

This limitation is a **conscious choice** to enable unique benefits. For example: Tempel's encrypted payloads contain metdata about the encryption algorithms and parameters used. This enables the **automatic selection of keys** in keychains, and enables **automatic and backwards-compatible algorithm and parameter upgrades over time**.

# How secure is Tempel?

The security of a framework like Tempel depends on:

1. Correct **implementation**  
   (1a.) Correct primitives  
   (1b.) Correct choice, use, and composition of primitives
2. Correct **use**

Unfortunately security depends on **all** of these being *simultaneously correct*.

In Tempel's case:

- (1a) is unlikely to be a problem since Tempel does not implement ("roll") its own cryptographic primitives. It instead uses the high-quality and extensively tested facilities provided natively by the JVM.
- (1b) is inevitably a risk whenever using a high-level framework like Tempel. My hope is that Tempel's simple protocols and formats are unlikely to be substantially incorrect and should be relatively easy to review/audit, and to keep updated with evolving best practices.
- (2) is inevitably a risk whenever using cryptography of any kind. My hope is that Tempel's high-level API and beginner-oriented documentation may actually help reduce the likelihood of mistakes here.

Ultimately you will need to assess for yourself:

- **How valuable** the security of your data is (/ how motivated an attacker might be)
- **How complex** your own needs are (custom protocols that may affect (2), etc.)
- **What alternatives** you may have (i.e. comparative risks)

Please be **very careful** evaluating Tempel and/or other cryptographic libraries/frameworks before use, especially **new** libraries/frameworks like Tempel!

# Is there a risk of data loss?

**Yes**, unfortunately any time you encrypt data you **inevitably** introduce the risk of losing that data:

- **Bugs and/or misuse** could lead to the data being undecryptable.
- **Accidental loss of decryption key/s** could lead to the data being undecryptable.

It is **critical** to always:

1. Test that data being encrypted **can be successfully decrypted** before discarding the original data.
2. Ensure that **appropriate backups** are made **and tested** of the original data, and/or decryption keys.

Please err on the side of being **overly cautious**.

# How fast is Tempel?

Tempel is a pretty thin wrapper over the JVM's native crypto facilities and **shouldn't add significant overhead itself**.

As for what performance to expect from the JVM's native crypto facilities - that depends a lot on your **specific hardware and configuration** (selected algorithms, work factors, etc.).

Both encryption and decryption *can* be slow and computationally expensive.

To get a realistic idea of performance, I'd recommend **benchmarking in your own environment** with your actual configuration and data.

# Why not just use the JVM's crypto API?

The JVM offers flexible and well-implemented crypto facilities, but they tend to be low-level in nature and are often **difficult to use correctly in practice**.

The same can be said for even excellent libraries like [Bouncing Castle](https://www.bouncycastle.org/).

Understanding what (not) to use and how to compose primitives into a coherent whole can require significant domain experience and/or research. **Mistakes can be costly** - difficult to correct, and potentially insecure.

Tempel uses the JVM's crypto API, but wraps it to:

1. Provide an idiomatic Clojure experience
2. Work at a higher level (see [examples](2-Examples.md))
3. Choose reasonable defaults, and highlight important choices
4. Provide future-proof data formats with auto-updated algorithms and work factors over time

# Isn't it dangerous to "roll your own crypto?"

Tempel does not implement ("roll") its own cryptographic primitives, though it *does* necessarily implement its own higher-level protocols and data formats.

See [here](#how-secure-is-tempel) for more info about Tempel's security risks.

# How does Tempel compare to Buddy?

**tl;dr**: Tempel may be a possible alternative for some (but not all) parts of [Buddy](https://github.com/funcool/buddy). There's functionality overlap, but Buddy offers some facilities that Tempel does not and vice versa.

#### Tempel's limitations

- No public API for *low-level cryptographic functionality* as in [buddy-core](https://github.com/funcool/buddy-core), [buddy-hashers](https://github.com/funcool/buddy-hashers), etc.
- No *authorization* functionality as in [buddy-auth](https://github.com/funcool/buddy-auth)
- [No support](#can-i-decrypt-tempel-data-with-other-tools) for interop with other tools

#### Tempel's strengths

- A small, particularly easy-to-use high-level [API](./1-Getting-started#what-next) focused on [user keychains](./1-Getting-started#keychains) and keychain management.
- Data formats designed to easily support item-specific algorithms and parameters, and to support (auto)-updating these kinds of things over time.

#### Tempel's objectives

I've built a number of applications over the years that deal with encrypted user data. Tempel's focused on addressing the *real-world nuisances* that I've personally encountered most often.

These include things like:

- Long-term *key management*.
- Long-term *maintenance of algorithms and parameters* (scaling work factors and/or adjusting algorithms to keep up with best practice and moving hardware targets over time).
- A consistent and easy-to-use API for *encrypting data with backup keys* so that it's always possible to reset a user's password, even when the user's data is fully encrypted at rest and the user's key is never stored.
- A consistent and easy-to-use API for [AAD](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#help:aad), [AKM](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#help:akm), and [extracting public data](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#public-data) from encrypted payloads.
