(ns examples
  "Some basic Tempel usage examples."
  (:require
   [taoensso.tempel :as tempel]
   [taoensso.nippy  :as nippy]))

(comment (remove-ns 'examples))

;;;; README quick example

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

;;;; Basic `KeyChain` usage

;; Let's create a new `KeyChain` object for our user Alice.
;; We'll use this object any time we want to encrypt or decrypt data for Alice.

(defonce alice-keychain
  ;; A `KeyChain` for user Alice, created with the default options in `*config*`.
  (tempel/keychain {}))

(tempel/keychain? alice-keychain) ; => true

;; Eval a `KeyChain` to get some basic info about it:
alice-keychain
;; => KeyChain[{:n-sym 1, :n-prv 2, :n-pub 2, :secret? true} 0x424af8e5]
;; => 1 symmetric key, 2 private keys, 2 public keys
;; Note that this `KeyChain` contains secret data (private keys)!

;; Deref a `KeyChain` to get detailed info about it:
@alice-keychain
;; =>
;; {"1" {:key-algo :symmetric, :priority 0, :key-sym ChainKey, :length 32},
;;  "2" {:key-algo :rsa-3072,  :priority 1, :key-prv ChainKey, :key-pub ChainKey[]},
;;  "3" {:key-algo :dh-3072,   :priority 2, :key-prv ChainKey, :key-pub ChainKey[]}}

;; Note that Alice's `KeyChain` contains:
;;  - 1x 256  bit symmetric key
;;  - 1x 3072 bit RSA keypair (private + public)
;;  - 1x 3072 but DH  keypair (private + public)
;;
;; It's not important to understand yet what any of that means, these are
;; reasonable defaults that'll work well together to support the entire Tempel API.

;; The content of `KeyChain`s can be updated: keys can be added or removed,
;; and key priorities can be adjusted. But for many simple uses you won't need
;; to do any of that under normal circumstances.

;; For now just note that this `KeyChain` contains secret data (private keys)!
;; So if we want to store the chain (e.g. to DB), we should first encrypt it:

(defonce alice-encrypted-keychain
  ;; Same as `alice-keychain`, but encrypted using a secret password from Alice.
  (tempel/keychain-encrypt alice-keychain {:password "Alice's secret password"}))

;; We can always retrieve Alice's public keys, even without her password:
(tempel/public-data alice-encrypted-keychain)
;; => {:kind :encrypted-keychain, :version 1, :keychain #taoensso.tempel.keys.KeyChain[{:n-pub 2, :secret? false} 0x659d9061]}

;; And if we have her password, we can get back everything:
(tempel/keychain-decrypt alice-encrypted-keychain {:password "Alice's secret password"})
;; => KeyChain[{:n-sym 1, :n-prv 2, :n-pub 2, :secret? true} 0x8534bd]

;; Equality works as you'd expect for `KeyChain`s:
(=
  (tempel/keychain-decrypt alice-encrypted-keychain {:password "Alice's secret password"})
  alice-keychain) ; => true

;; So now that we have one or more `KeyChain`s, what can we do with them?
;;
;; See the examples for task-oriented ideas, and/or check the extensive docstrings of Tempel's main API functions:
;
;; - `encrypt-with-password`
;; - `encrypt-with-symmetric-key`
;; - `encrypt-with-1-keypair`
;; - `encrypt-with-2-keypairs`

;;;; Login system

;; We'll create and maintain a secret `KeyChain` for each user,
;; storing these only in their encrypted form.

(defonce my-users-db_
  ;; {<user-id> <encrypted-KeyChain>} or something equivalent for your real database
  (atom {}))

(defn get-encrypted-keychain
  "Returns user's encrypted `KeyChain`, or nil if no such user exists."
  [user-id]
  (get @my-users-db_ user-id))

;;; Create admin account

;; Let's start by manually creating a privileged admin account. We'll use this
;; account's `KeyChain` as a backup key when encrypting the `KeyChain`s of other
;; user accounts.

(defonce _create-admin-user
  (do
    (swap! my-users-db_ assoc "Admin"
      (tempel/keychain-encrypt (tempel/keychain)
        {:pbkdf-nwf :ref-2000-msecs      ; Override default in *config*
         :password  "admin-secret-password"}))
    nil))

(defonce admin-public-keychain
  ;; Public component of the admin user's `KeyChain`
  (:keychain (tempel/public-data (get-encrypted-keychain "Admin"))))

admin-public-keychain
;; => #taoensso.tempel.keys.KeyChain[{:n-pub 2, :secret? false} 0x47230e9]

;; Note that because of the high value of this admin account (it'll have access
;; to all other user data), we've chosen to override (increase) the default
;; password-stretching work factor (`:pbkdf-nwf`) from the `*config*` default
;; of ~100 msecs to ~2000 msecs.

;; This just means that we want it to take about 2 seconds to transform a
;; password to a key. The longer this takes, the more difficult/expensive it'll
;; make attempted brute-force attacks.

;; Note that it's a handy feature of Tempel to easily support different work
;; factors like this on a per-item basis.

;; See the `*config*` docstring for more info on the `:pbkdf-nwf` option, etc.

;; Note that it's a key feature

;;; Create user account

(defn user-create-new-account!
  "Creates a new `KeyChain` for user, and writes the encrypted `KeyChain` to DB.
  Returns the unencrypted `KeyChain`."
  [user-id user-password]

  (let [;; Create a new secret `KeyChain` for user.
        ;; This will include new random keys as specified in the `*config*` var.
        ;;
        ;; Default config should be reasonable for most users, but see the
        ;; var's docstring for details.
        unencrypted-keychain (tempel/keychain {})

        ;; Encrypt the user's `KeyChain` with their secret password.
        ;; Don't store password or unencrypted `KeyChain`!
        encrypted-keychain
        (tempel/keychain-encrypt unencrypted-keychain
          {:password   user-password
           :backup-key admin-public-keychain})]

    (swap! my-users-db_ assoc user-id encrypted-keychain)
    unencrypted-keychain))

(user-create-new-account! "Alice" "alice-secret-password")
(user-create-new-account! "Barry" "barry-secret-password")

;;; Log in

(defonce password-rate-limiter
  ;; Basic in-memory rate limiter to help protect against brute-force
  ;; attacks from the same user-id. In real applications you'll likely
  ;; want a persistent rate limiter for user-id, IP, etc.
  (tempel/rate-limiter
    {"1 attempt/s per 5 sec/s" [1        5000]
     "2 attempt/s per 1 min/s" [2 (* 1 60000)]
     "5 attempt/s per 5 min/s" [5 (* 5 60000)]}))

(comment
  (password-rate-limiter           "dummy-user-id")
  (password-rate-limiter :rl/reset "dummy-user-id"))

(defn user-log-in
  "Attempts to log user in.
  Returns user's unencrypted secret `KeyChain` on success, or throws."
  [user-id user-password]

  ;; Ensure a minimum runtime to help protect against timing attacks,
  ;; Ref. <https://en.wikipedia.org/wiki/Timing_attack>.
  (tempel/with-min-runtime 2000

    (if-let [rate-limited (password-rate-limiter user-id)]
      (throw (ex-info "Bad login attempt (rate limited)" {:limit-info rate-limited}))

      (or
        (when-let   [encrypted-keychain (get-encrypted-keychain user-id)]
          (when-let [decrypted-keychain
                     (tempel/keychain-decrypt encrypted-keychain
                       {:password user-password})]

            (password-rate-limiter :rl/reset user-id) ; Reset rate limiter
            decrypted-keychain))

        (throw
          (ex-info "Bad login attempt (bad user-id or password)"
            {:user-id user-id}))))))

(comment
  (password-rate-limiter :rl/reset "Alice")
  (user-log-in "Alice" "alice-secret-password") ; => Alice's secret `KeyChain`
  (user-log-in "Alice" "wrong-password")        ; => Throws
  )

;;; Change password

(defn user-change-password!
  "Attempts to change user's password.
  Returns user's unencrypted secret `KeyChain` on success, or throws.

  Note that the user's underlying `KeyChain` doesn't actually change, only
  the password used for its encrypted form.

  I.e. changing a user's password doesn't automatically rotate their chain's
  internal keys. This is a useful property since key changes can be disruptive
  and are actually rarely needed."
  [user-id [old-user-password new-user-password]]

  (tempel/with-min-runtime 2000
    (if-let [rate-limited (password-rate-limiter user-id)]
      (throw (ex-info "Bad login attempt (rate limited)" {:limit-info rate-limited}))

      (or
        (when-let [old-encrypted-keychain (get-encrypted-keychain user-id)]
          (when-let [decrypted-keychain
                     (tempel/keychain-decrypt old-encrypted-keychain
                       {:password old-user-password})]

            (let [new-encrypted-keychain
                  (tempel/keychain-encrypt decrypted-keychain
                    {:password new-user-password})]

              (password-rate-limiter :rl/reset user-id)
              (swap! my-users-db_ assoc user-id new-encrypted-keychain)
              decrypted-keychain)))

        (throw
          (ex-info "Bad login attempt (bad user-id or password)"
            {:user-id user-id}))))))

(comment
  (password-rate-limiter :rl/reset "Alice")
  (user-change-password! "Alice" ["alice-secret-password" "alice-secret-password2"]) ; => Alice's secret `KeyChain`
  (user-change-password! "Alice" ["wrong-password"        "alice-secret-password2"]) ; => Throws
  )

;;; Reset forgotten password

;; This is where we'll make use of the backup admin key we setup earlier.

(defn user-reset-forgotten-password!
  "Uses Admin `KeyChain` to reset user's password and return their decrypted `KeyChain`."
  [user-id admin-password new-user-password]

  (let [encrypted-user-keychain  (get-encrypted-keychain user-id)
        encrypted-admin-keychain (get-encrypted-keychain "Admin")

        decrypted-admin-keychain
        (tempel/keychain-decrypt encrypted-admin-keychain
          {:password admin-password})

        decrypted-user-keychain
        (tempel/keychain-decrypt encrypted-user-keychain
          {:backup-key decrypted-admin-keychain})

        new-encrypted-user-keychain
        (tempel/keychain-encrypt decrypted-user-keychain
          {:password   new-user-password
           :backup-key admin-public-keychain})]

    decrypted-user-keychain))

(user-reset-forgotten-password! "Alice" "admin-secret-password" "alice-secret-password")

;;; Ring sessions

;; What to do once a user has successfully logged in and you have their
;; unencrypted `KeyChain` handy?

;; One common pattern is to add the user's unencrypted `KeyChain` to their
;; server-side session so that future requests from that user have easy access
;; to the `KeyChain` and therefore to the user's private (encrypted) data.

;; When the user later logs out (or the user's session expires), the unencrypted
;; `KeyChain` can be discarded.

;;; Advanced variation

;; If you really want to minimize the amount of time that a user's unencrypted
;; `KeyChain` is held (even in memory), an advanced pattern is possible.

;; On successful login:
;;   1. Encrypt a **temporary copy** of the user's `KeyChain` with a random key
;;   2. Stick this **encrypted** `KeyChain` copy into the user's session
;;   3. Send the random key to the user's client (browser, etc.), then discard it
;;   4. Ensure that the client includes this key with every subsequent request

;; This way, each request from the user contains the random key necessary to
;; access the user's `KeyChain` - but only for the duration of the request. The
;; user's unencrypted `KeyChain` is otherwise never present on the server.

;; The above process can be made convenient with a simple Ring middleware to add
;; a delayed decrypted `KeyChain` to Ring requests that contain the decryption
;; key relayed by the requesting client.

;; Performance tip: when using this approach, make sure to use a random byte[]
;; key for step 1 rather than a random **password**. Passwords will involve
;; expensive and unnecessary key stretching. Compare:

(let [rand-str "yhH4xtEy4A2P6uA9vwPvY8Z8WpSjuSVLfWqHfVZ4gkFVy82fdphHvjWURvCz"]
  (tempel/keychain-encrypt alice-keychain {:key-sym (tempel/as-ba rand-str)}) ; Fast
  (tempel/keychain-encrypt alice-keychain {:password              rand-str})  ; Slow!
  )

;;; Key management

;; Tempel includes the following utils for basic key management:
;;   - `keychain-add-symmetric-key`
;;   - `keychain-add-asymmetric-keypair`
;;   - `keychain-remove`
;;   - `keychain-update-priority`
;;   - `keychain-normalize-priorities`

;; These should cover the most common needs. More advanced key management
;; can quickly become a complex topic and is beyond the scope of Tempel's
;; built-in API or these docs.

;;;; Basic encryption

;;; Symmetric encryption with a password
(let [ba-secret-data (nippy/freeze {:my-secret-data? true})
      ba-encrypted   (tempel/encrypt-with-password ba-secret-data "my-secret-password")
      ba-decrypted   (tempel/decrypt-with-password ba-encrypted   "my-secret-password")]
  (= (nippy/thaw ba-decrypted) {:my-secret-data? true}))

;;; Symmetric encryption with `KeyChain`
(let [alice-secret-keychain (tempel/keychain {}) ; Only Alice will have this
      ba-secret-data (nippy/freeze {:my-secret-data? true})
      ba-encrypted   (tempel/encrypt-with-symmetric-key ba-secret-data alice-secret-keychain)
      ba-decrypted   (tempel/decrypt-with-symmetric-key ba-encrypted   alice-secret-keychain)]
  (= (nippy/thaw ba-decrypted) {:my-secret-data? true}))

;;; Symmetric encryption with a byte[] key
(let [ba-secret-key  (tempel/rand-ba 32) ; Random 256-bit key
      ba-secret-data (nippy/freeze {:my-secret-data? true})
      ba-encrypted   (tempel/encrypt-with-symmetric-key ba-secret-data ba-secret-key)
      ba-decrypted   (tempel/decrypt-with-symmetric-key ba-encrypted   ba-secret-key)]
  (= (nippy/thaw ba-decrypted) {:my-secret-data? true}))

;;;; Send secret message to user

(let [alice-secret-keychain (tempel/keychain {}) ; Only Alice will have this
      alice-public-keychain ; Anyone may have this
      (:keychain
       (tempel/public-data
         (tempel/keychain-encrypt alice-secret-keychain
           {:password "alice-secret-password"})))

      ba-secret-data (nippy/freeze {:my-secret-data? true})
      ba-encrypted   (tempel/encrypt-with-1-keypair ba-secret-data alice-public-keychain)
      ba-decrypted   (tempel/decrypt-with-1-keypair ba-encrypted   alice-secret-keychain)]

  ;; Alice can decrypt the data:
  (= (nippy/thaw ba-decrypted) {:my-secret-data? true}))

;;;; Send secret message between 2 users

(let [alice-secret-keychain (tempel/keychain {}) ; Only Alice will have this
      barry-secret-keychain (tempel/keychain {}) ; Only Barry will have this

      alice-public-keychain ; Anyone may have this
      (:keychain
       (tempel/public-data
         (tempel/keychain-encrypt alice-secret-keychain
           {:password "alice-secret-password"})))

      barry-public-keychain ; Anyone may have this
      (:keychain
       (tempel/public-data
         (tempel/keychain-encrypt barry-secret-keychain
           {:password "barry-secret-password"})))

      ba-secret-data        (nippy/freeze {:my-secret-data? true})
      ba-encrypted          (tempel/encrypt-with-2-keypairs ba-secret-data alice-public-keychain barry-secret-keychain)
      ba-decrypted-by-alice (tempel/decrypt-with-2-keypairs ba-encrypted   alice-secret-keychain barry-public-keychain)
      ba-decrypted-by-barry (tempel/decrypt-with-2-keypairs ba-encrypted   barry-secret-keychain alice-public-keychain)]

  ;; Both Alice and Barry can decrypt the data:
  [(= (nippy/thaw ba-decrypted-by-alice) {:my-secret-data? true})
   (= (nippy/thaw ba-decrypted-by-barry) {:my-secret-data? true})])

;;;; Send secret message between >2 users

;; This is an advanced version of the last example and would require a custom
;; scheme, for example:

;; - Have 1 user act as the group/room owner.
;; - Have the owner generate a random symmetric key for the group/room.
;; - Have the owner distribute the shared key to every other user via
;;   `encrypt-with-1-keypair` or `encrypt-with-2-keypairs`, etc.

;;;; Public data

;; Tempel has extensive support for "**Additional Authenticated Data**" /
;; "**Additional Associated Data**", see `help:aad` for details.

;; And see `public-data` for a util that can help identify Tempel output,
;; and access public (unencrypted) info embedded in Tempel output.

;;;; Signing

;; See the `tempel/sign` and `tempel/signed` docstrings for details.
