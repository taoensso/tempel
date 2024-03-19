# Disclaimer

**Important**: while Tempel has been written and tested with care, the nature of the problem domain inevitably means that bugs and/or misuse can be **especially harmful and/or easy to make**.

Bugs and/or misuse could lead to [security vulnerabilities](./3-FAQ#how-secure-is-tempel) or even [permanent data loss](./3-FAQ#is-there-a-risk-of-data-loss).

Please be **very careful** evaluating Tempel and/or other cryptographic libraries/frameworks before use, especially new libraries/frameworks like Tempel!

# Setup

Add the [relevant dependency](../#latest-releases) to your project:

```clojure
Leiningen: [com.taoensso/tempel               "x-y-z"] ; or
deps.edn:   com.taoensso/tempel {:mvn/version "x-y-z"}
```

Since Tempel operates primarily on **byte arrays**, you may also want to use something like [Nippy](https://github.com/taoensso/nippy) to help convert your Clojure data types to/from these byte arrays:

```clojure
;;; Optional
Leiningen: [com.taoensso/nippy               "x-y-z"] ; or
deps.edn:   com.taoensso/nippy {:mvn/version "x-y-z"}
```

Setup your namespace imports:

```clojure
(ns my-app
  (:require
    [taoensso.tempel :as tempel]
    [taoensso.nippy  :as nippy] ; Optional, but useful
    ))
```

You may also want to add a dependency for [`com.lambdaworks/scrypt`](https://github.com/wg/scrypt):

```clojure
;;; Optional
Leiningen: [com.lambdaworks/scrypt               "1.4.0"] ; or
deps.edn:   com.lambdaworks/scrypt {:mvn/version "1.4.0"}
```

This is a Java implementation of [⧉ scrypt](https://en.wikipedia.org/wiki/Scrypt), a particularly secure [⧉ key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function). By default, Tempel will use the following when generating keys from passwords:

- [⧉ scrypt](https://en.wikipedia.org/wiki/Scrypt) when it is present, or
- [⧉ pbkdf2](https://en.wikipedia.org/wiki/PBKDF2) otherwise

This isn't too important to understand in detail. My recommendation is just to include the above scrypt dependency unless you have a specific reason not to.

# Usage

## Quick intro

Tempel is basically a toolkit to help **encrypt and decrypt data** in a variety of situations.

- Encryption always requires an **encryption key**.
- Decryption always requires the **related decryption key**.

There's broadly two kinds of encryption to be aware of:

1. [⧉ Symmetric encryption](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) is the easiest to understand and is just like using a password. The *same* secret "**symmetric key**" will be used for both encryption *and* decryption (hence the term "symmetric"). The most common symmetric algorithm is [⧉ AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard).
   
2. [⧉ Asymmetric encryption](https://en.wikipedia.org/wiki/Public-key_cryptography) (or "public-key" encryption) is more complex, but also supports a wider range of situations. Asymmetric encryption uses "keypairs". A **keypair** consists of two *different but related* keys (hence the term "asymmetric"): one secret "**private key**", and one related "**public key**" that's generally safe to share (i.e. not secret). Some common asymmetric algorithms are [⧉ RSA](https://en.wikipedia.org/wiki/RSA_(algorithm)) and [⧉ Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).

In many cases, asymmetric encryption schemes will also use symmetric encryption. These "**hybrid schemes**" will generally use asymmetric techniques to safely exchange a **symmetric key** between parties. Further communications can then safely be done via symmetric encryption (which is usually simpler and faster).

## Challenges

Working with encryption can be tough. Some of the most stressful and error-prone challenges in practice include:

- Understanding **what keys you'll need** (algorithms, parameters, etc.).
- Understanding how **the various algorithms/schemes fit together** (when and how to use hybrid schemes, etc.).
- **Maintaining best-practices over time** (e.g. auto migrating from compromised algorithms, auto incrementing work factors, etc.).
- **Key management** (key rotation, password resets, admin backups, etc.).

Many of these can be **tough to get right** - needing non-trivial understanding, experience, and effort. And getting even one thing wrong can mean **compromised or completely inaccessible data**.

Tempel was designed to try help with each of these, letting you **focus on your application** - not on the rat's nest of becoming a security expert.

## Keychains

As mentioned in the [quick intro](#quick-intro), encryption means **keys**. You'll need various kinds of keys to interact with Tempel's API.

But instead of bogging you down with details, Tempel uses a concept called "**keychains**".

Analogous to physical keychains, these are Clojure objects that hold 0 or more keys of various types for various purposes.

Tempel `KeyChain`s:

- Can be evaluated for basic info
- Can be derefed for detailed info
- Can be tested for equality
- Can be easily and securely de/serialized
- Include a built-in API for easy key management (addition/removal, naming, prioritization, etc.)

Let's create a new `KeyChain` object for our user Alice. We'll use this object any time we want to encrypt or decrypt data for Alice.

```clojure
(defonce alice-keychain
  ;; A `KeyChain` for user Alice, created with the default options in `*config*`.
  (tempel/keychain {}))

(tempel/keychain? alice-keychain) ; => true
```

Eval a `KeyChain` to get some basic info about it:

```clojure
alice-keychain
;; => KeyChain[{:n-sym 1, :n-prv 2, :n-pub 2, :secret? true} 0x424af8e5]
;; => 1 symmetric key, 2 private keys, 2 public keys
;; Note that this `KeyChain` contains secret data (private keys)!
```

Deref a `KeyChain` to get detailed info about it:

```clojure
@alice-keychain
;; =>
;; {"1" {:key-algo :symmetric, :priority 0, :key-sym ChainKey, :length 32},
;;  "2" {:key-algo :rsa-3072,  :priority 1, :key-prv ChainKey, :key-pub ChainKey[]},
;;  "3" {:key-algo :dh-3072,   :priority 2, :key-prv ChainKey, :key-pub ChainKey[]}}
```

Note that Alice's `KeyChain` contains:

- 1x 256 bit symmetric key
- 1x 3072 bit RSA keypair (private + public)
- 1x 3072 but DH  keypair (private + public)

It's not important to understand yet what any of that means. These are reasonable defaults that'll work well together to support the entire Tempel API. Each key/pair was randomly and securely generated when we called `tempel/keychain`, based on the options present in `tempel/*config*`.

`tempel/*config*` is an important var. Its [default value](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#default-config) should be reasonable for most users, but it'd be worth at least familiarizing yourself with what's in there. [Its docstring](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#*config*) includes extensive documentation.

The content of `KeyChain`s can be updated: keys can be added or removed, and key priorities can be adjusted. But for many simple uses you won't need to do any of that under normal circumstances.

For now just note that this `KeyChain` contains secret data (private keys)! So if we want to store the chain (e.g. to DB), we should first encrypt it:

```clojure
(defonce alice-encrypted-keychain
  ;; Same as `alice-keychain`, but encrypted using a secret password from Alice.
  (tempel/keychain-encrypt alice-keychain {:password "Alice's secret password"}))
```

We can always retrieve Alice's public keys, even without her password:

```clojure
(tempel/public-data alice-encrypted-keychain)
;; => {:kind :encrypted-keychain, :version 1, :keychain #taoensso.tempel.keys.KeyChain[{:n-pub 2 :secret? false} 0x659d9061]}
```

And if we have her password, we can get back everything:

```clojure
(tempel/keychain-decrypt alice-encrypted-keychain {:password "Alice's secret password"})
;; => KeyChain[{:n-sym 1, :n-prv 2, :n-pub 2, :secret? true} 0x8534bd]
```

Equality works as you'd expect for `KeyChain`s:

```
(=
  (tempel/keychain-decrypt alice-encrypted-keychain {:password "Alice's secret password"})
  alice-keychain) ; => true
```

## API overview

Tempel's API is small, easy to use, easy to browse, and has extensive beginner-oriented docstrings.  It includes:

### Keychain basics

`KeyChain`s are the main way you'll interact with the rest of Tempel's API:

| Function                                                                                                    | Use to                                                               |
| ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| [`keychain`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#keychain)                 | Create a new `KeyChain`, default opts are reasonable.                |
| [`keychain-encrypt`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#keychain-encrypt) | Encrypt a `KeyChain` (with password, byte[], or another `KeyChain`). |
| [`keychain-decrypt`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#keychain-decrypt) | Decrypt a `KeyChain` (with password, byte[], or another `KeyChain`). |

- You'll usually have 1 `KeyChain` per user: created and encrypted on sign-up, then decrypted on log-in and retained while the user remains logged in.
- Deref a `KeyChain` to see its contents.
- The default `keychain` options will return a `KeyChain` that includes all the keys necessary to fully support Tempel's entire API.

### Data protection

| Function | Complement | Use to |
| ---- | ---- | ---- |
| [`encrypt-with-password`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#encrypt-with-password) | [`decrypt-with-password`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#decrypt-with-password) | Encrypt & decrypt data with the same password.
| [`encrypt-with-symmetric-key`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#encrypt-with-symmetric-key) | [`decrypt-with-symmetric-key`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#decrypt-with-symmetric-key) | Encrypt & decrypt data with the same `KeyChain` or byte[].
| [`encrypt-with-1-keypair`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#encrypt-with-1-keypair) | [`decrypt-with-1-keypair`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#encrypt-with-1-keypair) | Encrypt data with recipient's public `KeyChain`. Only the recipient can decrypt.
| [`encrypt-with-2-keypairs`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#encrypt-with-2-keypairs) | [`decrypt-with-2-keypairs`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#encrypt-with-2-keypairs) | Encrypt data with sender's private `KeyChain` and recipient's public `KeyChain`. Either party can decrypt.
| [`sign`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#sign) | [`signed`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#signed) | Sign data, and verify signed data. Useful for proving ownership, detecting tampering, etc.

### Supporting utils

Miscellaneous stuff that's used less frequently:

| Function                                                                                                                                  | Use to                                                               |
| ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| [`public-data`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#public-data)                                         | Return any public (unencrypted) data associated with encrypted data. |
| [`keychain-add-symmetric-key`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#keychain-add-symmetric-key)           | Add symmetric key/s to a `KeyChain`.                                 |
| [`keychain-add-asymmetric-keypair`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#keychain-add-asymmetric-keypair) | Add asymmetric keypair/s to a `KeyChain`.                            |
| [`keychain-remove`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#keychain-remove)                                 | Remove key/s from a `KeyChain`.                                      |
| [`keychain-update-priority`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#keychain-update-priority)               | Update priority of key/s in a `KeyChain`.                            |

- Manual keychain management is rarely needed in practice, but useful when you need it!
- See [`help:aad`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#help:aad) for info about Tempel's "Additional Authenticated Data" (AAD) support.
- See [`help:akm`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#help:akm) for info about Tempel's "Additional Keying Material" (AKM) support.
- See [`*config*`](https://cljdoc.org/d/com.taoensso/tempel/CURRENT/api/taoensso.tempel#*config*) for info about Tempel's global config options.

## What next

See the [examples](./2-Examples) for task-oriented ideas!
