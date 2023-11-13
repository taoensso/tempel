# Disclaimer

**Important**: while Tempel has been written and tested with care, the nature of the problem domain inevitably means that bugs and/or misuse can be **especially harmful and/or easy to make**.

Bugs and/or misuse could lead to [security vulnerabilities](./3-FAQ#how-secure-is-tempel) or even [permanent data loss](./3-FAQ#is-there-a-risk-of-data-loss).

Please be **very careful** evaluating Tempel and/or other cryptographic libraries/frameworks before use, especially new libraries/frameworks like Tempel!

# Setup

Add the [relevant Tempel dependency](../#latest-releases) to your project:

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
   
2. [⧉ Asymmetric encryption](https://en.wikipedia.org/wiki/Public-key_cryptography) (or "public-key" encryption) is more complex, but also supports a wider range of situations. Asymmetric encryption uses "key pairs". A **key pair** consists of two *different but related* keys (hence the term "asymmetric"): one secret "**private key**", and one related "**public key**" that's generally safe to share (i.e. not secret). Some common asymmetric algorithms are [⧉ RSA](https://en.wikipedia.org/wiki/RSA_(algorithm)) and [⧉ Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).

In many cases, asymmetric encryption schemes will also use symmetric encryption. These "**hybrid schemes**" will generally use asymmetric techniques to safely exchange a **symmetric key** between parties. Further communications can then safely be done via symmetric encryption (which is usually simpler and faster).

## Challenges

Working with encryption can be tough. Some of the challenges include:

- Understanding **what keys you'll need** (key algorithms, parameters, etc.)
- Understanding how **the various algorithms/schemes fit together** (e.g. when and how to use hybrid schemes)
- Managing keys (changing algorithms or parameters, rotating keys, etc.)
- Doing all the above without introducing vulnerabilities

Tempel was designed to try help with each of these. Its API is **task oriented**, and tries to shield non-experts from unnecessary implementation details.

## Keychains

As mentioned in the [quick intro](#quick-intro), encryption means **keys**. You'll need various kinds of keys to interact with Tempel's API.

But instead of bogging you down with details, Tempel uses a concept called "**key chains**".

Analogous to physical key chains, these are Clojure objects that hold 0 or more keys of various types for various purposes.

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
- 1x 3072 bit RSA key pair (private + public)
- 1x 3072 but DH  key pair (private + public)

It's not important to understand yet what any of that means. These are reasonable defaults that'll work well together to support the entire Tempel API. Each key/pair was randomly and securely generated when we called `tempel/keychain`, based on the options present in `tempel/*config*`.

`tempel/*config*` is an important var. Its [default value](https://taoensso.github.io/tempel/taoensso.tempel.html#var-default-config) should be reasonable for most users, but it'd be worth at least familiarizing yourself with what's in there. [Its docstring](https://taoensso.github.io/tempel/taoensso.tempel.html#var-*config*) includes extensive documentation.

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

## What next

So now that we have one or more `KeyChain`s, what can we do with them?

See the [examples](./2-Examples) for task-oriented ideas, and/or check the extensive docstrings of Tempel's main API functions:

- [`encrypt-with-password`](https://taoensso.github.io/tempel/taoensso.tempel.html#var-encrypt-with-password)
- [`encrypt-with-symmetric-key`](https://taoensso.github.io/tempel/taoensso.tempel.html#var-encrypt-with-symmetric-key)
- [`encrypt-with-1-keypair`](https://taoensso.github.io/tempel/taoensso.tempel.html#var-encrypt-with-1-keypair)
- [`encrypt-with-2-keypairs`](https://taoensso.github.io/tempel/taoensso.tempel.html#var-encrypt-with-2-keypairs)
- [`sign`](https://taoensso.github.io/tempel/taoensso.tempel.html#var-sign)