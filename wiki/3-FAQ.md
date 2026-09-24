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

# Can I use the same key for different purposes?

**Best avoided**. Tempel's current data formats don't bind keys to a purpose, so prefer a separate key/pair for each of: encrypting keychains, encrypting other data, and backup keys.

This matters most if your application can be made to decrypt data supplied by an attacker and reveal the result. An encrypted keychain could then be presented as ordinary encrypted data, revealing its private keys.

If you must share a key or password, use a different [AKM](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#help:akm) for each purpose. AKM doesn't protect backup recovery though, so backup keys should always be kept for backup use only.

Decrypting with `:require-hmac? true` (see [`*config*`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#*config*)) also prevents one kind of Tempel output (e.g. an encrypted keychain) from being read as another. You can use this if none of your data was written with `:embed-hmac? false`.

# Can I use OWASP's password recommendations?

Yes, for Tempel's **password stretching**. Tempel uses passwords to encrypt data; it doesn't provide a standalone password hash/verify API.

[OWASP recommends](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) Argon2id, or scrypt when Argon2id isn't available. Tempel doesn't currently support Argon2id. To use its scrypt support, add the [optional dependency](./1-Getting-started#setup), then pass these options to `keychain-encrypt` or `encrypt-with-password`:

```clojure
{:pbkdf-algo :scrypt-r8p1-v1
 :pbkdf-nwf  16} ; N=2^17, r=8, p=1 (about 128 MiB per derivation)
```

For PBKDF2-HMAC-SHA-256, OWASP recommends at least 600,000 iterations:

```clojure
{:pbkdf-algo :pbkdf2-hmac-sha-256-v1
 :pbkdf-nwf  586} ; ~600k iterations
```

These match the linked work-factor recommendations as of September 2026. The `:ref-*-msecs` presets describe approximate runtimes on reference hardware, not OWASP requirements.

Benchmark on your own hardware, allowing for concurrent logins. Tempel stores the chosen parameters with each encrypted item, so changing your config affects new encryptions only. To upgrade existing keychains, decrypt and re-encrypt them with the new settings when users next log in.

# Can I use SSO or MFA with Tempel?

**Yes**, but authenticating a user and decrypting their data are separate steps.

With **SSO** (e.g. OpenID Connect), a successful login doesn't by itself provide a decryption key. A simple approach is to ask for a separate password to unlock the user's `KeyChain`. Alternatively, your application can manage the encryption keys and grant access after SSO login, though this means the application can decrypt data without the user. Don't use access tokens or ID tokens as encryption keys: they can expire or change.

With **MFA**, check both the password and the second factor before granting access or putting the decrypted `KeyChain` in a session. Tempel can handle the password check as in the [login example](./2-Examples#log-in); use your authentication library/provider to verify the second factor.

For TOTP, you can store the long-lived TOTP secret inside the user's encrypted data and check the code after decryption. The short-lived code itself isn't suitable as an encryption password. This protects login, but doesn't add a second factor to offline decryption of a stolen password-encrypted keychain.

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
