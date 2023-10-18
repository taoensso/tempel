(ns taoensso.tempel
  "Data security framework for Clojure.

  See the GitHub page (esp. Wiki) for info on motivation and design:
    <https://github.com/taoensso/tempel>

  See `df.clj` for data formats.
  All formats intended to support non-breaking future updates.

  Abbreviations:
    pbkdf - password based key derivation function
    aad   - additional associated data (see also `aad-help`)
    akm   - additional keying material (see also `akm-help`)
    kek   - key encryption key (key used to encrypt another key)
    cnt   -           content
    ecnt  - encrypted content"

  {:author "Peter Taoussanis (@ptaoussanis)"}
  (:require
   [taoensso.encore :as enc  :refer [have have?]]
   [taoensso.encore.bytes :as bytes]
   [taoensso.tempel.df    :as df]
   [taoensso.tempel.impl  :as impl]
   [taoensso.tempel.pbkdf :as pbkdf]
   [taoensso.tempel.keys  :as keys]))

(comment
  (remove-ns 'taoensso.tempel)
  (:api (enc/interns-overview)))

(enc/assert-min-encore-version [3 71 0])

;;;; TODO
;; - Eval some of Signal's work for possible inclusion as higher-level API?
;;   It's not currently obvious that any of these are particularly interesting.
;;
;;   - X3DH ("Extended Triple Diffie-Hellman") key agreement protocol, Ref. <https://signal.org/docs/specifications/x3dh/>
;;     - Provides forward secrecy and cryptographic deniability.
;;     - Users have:
;;       - 1x permanent identity keypair, replaced only if private key is lost, pub on server
;;       - nx one-time "pre-key" keypairs, signed by identkey, updated regularly (e.g. weekly), sigs on server
;;
;;   - "Double Ratchet" message protocol, Ref. <https://www.signal.org/docs/specifications/doubleratchet/>
;;     - Uses unique key for each message in conversation.
;;     - Keys generated such that a leaked key for msg n leaves other
;;       (earlier + later) keys ~secure.

;;;; Aliases

(enc/defaliases
  enc/str->utf8-ba
  enc/utf8-ba->str
  bytes/as-ba

  impl/with-srng
  impl/with-srng-insecure-deterministic!!!
  impl/keypair-create
  impl/keypair-creator
  pbkdf/pbkdf-nwf-estimate

  keys/chainkey?
  keys/keychain?
  keys/keychain
  keys/keychain-encrypt
  keys/keychain-decrypt
  keys/keychain-add-symmetric-key
  keys/keychain-add-asymmetric-keypair
  keys/keychain-update-priority
  keys/keychain-normalize-priorities
  keys/keychain-remove

  #_{:alias encrypt-keychain, :src keychain-encrypt, :doc "Alias for `keychain-encrypt`"}
  #_{:alias decrypt-keychain, :src keychain-decrypt, :doc "Alias for `keychain-decrypt`"})

;;;; Doc vars

(def aad-help
  "\"Additional Authenticated Data\" (AAD) is optional arbitrary byte[] data that
  may be provided to many of Tempel's API functions (e.g. `encrypt-with-X` when
  using an AEAD cipher).

  When so provided, AAD will be embedded *UNENCRYPTED* with the API function's
  output byte[].

  It may then later be retrieved:
    - Without verification: using `public-data` (see its docstring for details).
    - With    verification: using the appropriate complementary API function
                            (e.g. `decrypt-with-X`).

  Verification in this context means confirmation of:
    1. Data integrity (the data is intact, and unmodified)
    2. Authenticity (the data was indeed created/signed/etc. by the expected key).

  Examples of common AAD content:
    - Metadata like the sender, receiver, timestamp, etc.
    - Routing information
    - A description of the encrypted content
    - File or data integrity checks (hashes, etc.)
    - Cryptographic signatures
    - Arbitrary Clojure data via Nippy, Ref. <https://github.com/taoensso/nippy>"

  "See docstring")

(def akm-help
  "\"Additional Keying Material\" (AKM) is optional arbitrary byte[] data that
  may be provided to many of Tempel's API functions (e.g. `encrypt-with-X`).

  When so provided, AKM will act as additional secret material to supplement any
  main cryptographic keys, and so enhance security through increased resistance
  to certain types of attacks, etc.

  When an AKM is provided to an API function (e.g. `encrypt-with-X`), the same
  AKM *must* be provided to the function's complement (e.g. `decrypt-with-X`).

  In some contexts, an AKM may also be known as \"Shared Keying Material\" (SKM).

  Examples of common AKM content:
    - Metadata like the sender and receiver of an encrypted message
    - Random numbers or Nonces stored or transmitted separately
    - Key derivation parameters
    - Protocol-specific values
    - Security credentials or certificates
    - Arbitrary Clojure data via Nippy, Ref. <https://github.com/taoensso/nippy>"

  "See docstring")

;;;; Config

(enc/defonce default-keypair-creator_
  "Default stateful `KeyPair` generator with options:
  {:buffer-len 16, :n-threads [:perc 10]}"
  (delay (impl/keypair-creator {:buffer-len 16, :n-threads [:perc 10]})))

(comment (@default-keypair-creator_ :rsa-1024))

(def default-config
  "Default initial value for `*config*`."

  ;; Recommended pairing:
  ;;   - 128-bit AES with 128-bit salt, 3072-bit  RSA/DH
  ;;   - 256-bit AES with 256-bit salt, 4096-bit+ RSA/DH

  {:hash-algo           :sha-256
   :pbkdf-algo          pbkdf/pbkdf-kit-best-available #_:best-available
   :pbkdf-nwf           :ref-100-msecs
   :sym-cipher-algo     :aes-gcm-128-v1

   :keypair-creator     default-keypair-creator_
   :symmetric-keys      [:random]
   :asymmetric-keypairs [:rsa-3072 :dh-3072]

   :embed-key-ids?      true})

(enc/defonce ^:dynamic *config*
  "Tempel's behaviour is controlled in two ways:
    1. Through options manually provided in calls to its API functions.
    2. Through options in this `*config*` map.

  Any time an API function uses config options, the relevant config keys will
  be mentioned in that function's docstring.

  As a convenience, relevant config options (2) can also be overridden through
  call options (1). For example, these are equivalent:

    (binding [*config* (assoc *config* :hash-algo :sha-256)]
      (encrypt-with-password ba-content password {}))

    (encrypt-with-password ba-content password {:hash-algo :sha-256})

  Options:

     Default values (*) should be sensible for most common use cases.

    `:hash-algo` ∈ #{:md5 :sha-1 *:sha-256 :sha-512}
      Hash algorithm used for internal HMACs, etc.
      Default: `:sha-256`, there's usually no good reason to change this.

    `:pbkdf-algo` ∈ #{*:scrypt-r8p1-v1 :pbkdf2-hmac-sha-256-v1}
      Algorithm to use for password-based key stretching.
      Default: `:scrypt-r8p1-v1` when `com.lambdaworks.crypto.SCrypt` is available,
      or `:pbkdf2-hmac-sha-256-v1` otherwise.

    `:pbkdf-nwf`
      ∈ #{:ref-10-msecs :ref-50-msecs *:ref-100-msecs :ref-200-msecs :ref-500-msecs
          :ref-1000-msecs :ref-2000-msecs :ref-5000-msecs <unsigned-short>}

      Normalized work factor (nwf) that describes how much computational effort
      should be used for password stretching.

      More effort means more resistance to brute-force attacks, but also more time
      and resources spent during normal operation.

      The `:ref-<num>-msecs` keywords take approximately the described amount of
      time on a 2020 M1 Macbook Pro. See also `pbkdf-nwf-estimate` docstring.

      Default: `:ref-100-msecs`, a reasonable value for many logins.

    `:sym-cipher-algo` ∈ #{*:aes-gcm-128-v1 :aes-gcm-256-v1}
      The symmetric cipher algorithm to use. A cipher that supports \"AEAD\"
      (Authenticated Encryption with Associated Data) must generally be provided
      in order to use `:ba-aad` options (see `aad-help` docstring).

      Default: `:aes-gcm-128-v1`, a good general-purpose symmetric cipher with
      AEAD support.

      Note that the 256 bit AES cipher is not necessarily stronger than the 128
      bit, and may even be weaker due to possible unique attack vectors
      (Ref. <https://goo.gl/qU4CCV>).

    `:keypair-creator` ∈ #{<function> <delay>}
      The function to use when generating asymmetric keypairs.
      See the `keypair-create` and `keypair-creator` docstrings for details.

      Default: `default-keypair-creator_`, which uses up to 10% of threads
      to buffer up to 16 keypairs per type.

      This is often something you'll want to customize.

    `:symmetric-keys`
      Symmetric keys to add to new `KeyChain`s.
      See the `keychain` docstring for details.

      Default: a single random symmetric key.

    `:asymmetric-keypairs`
      Asymmetric keypairs to add to new `KeyChain`s.
      See the `keychain` docstring for details.

      Default:
        - A single new `:rsa-3072` keypair, and
        - A single new `:dh-3072`  keypair

      Together these support all common Tempel functionality, and are a
      reasonable choice in most cases.

    `:embed-key-ids?`
      Should key ids be embedded in output when using `KeyChain`s?
      This will allow the automatic selection of relevant keys during decryption,
      in exchange for leaking (making public) the ids used for encryption.

      This is often convenient, and *usually* safe unless you have custom key ids
      that contain private information and/or if it's important that you not leak
      information about which public `KeyChain`s might contain the necessary keys.

      Default: true.
      You may want to disable this for maximum security, but note that doing so
      may complicate decryption. See the Tempel Wiki for details."

  default-config)

(defn ^:no-doc get-config "Implementation detail" [opts] (enc/fast-merge *config* opts))
(comment (get-config {}))

;;;; Public data

(defn public-data
  "Given an encrypted Tempel byte[], returns a map of *UNVERIFIED* public
  (unencrypted) data embedded in the byte[].

  Possible keys:
    `:ba-aad`          - See `aad-help` docstring.
    `:keychain`        - Public-key part of encrypted `KeyChain`
    `:key-id`          - See `:embed-key-ids?` option of `encrypt-X` API
    `:receiver-key-id` - ''
    `:sender-key-id`   - ''
    `:key-algo`        - ∈ #{:rsa-<nbits> :dh-<nbits> :ec-<curve>}
    `:version`         - Integer version of data format (1, 2, etc.).
    `:kind`            - ∈ #{:encrypted-with-symmetric-key
                             :encrypted-with-password
                             :encrypted-with-1-keypair
                             :encrypted-with-2-keypairs
                             :encrypted-keychain
                             :signed}

  NB: provides *UNVERIFIED* data that could be corrupted or forged!
  For cryptographically verified data, use the appropriate API function
  (e.g. `decrypt-X`) instead."

  #_df/reference-data-formats
  [ba-tempel-output]
  (bytes/with-in [in] ba-tempel-output
    (let [_       (df/read-head! in)
          env-kid (df/read-kid   in :envelope)
          ;; [kind version] (re-find #"^(\w+)-v(\d+)$" (name env-kid))
          asm enc/assoc-some]

      (case env-kid
        :encrypted-with-symmetric-key-v1
        (let [?ba-aad (bytes/read-dynamic-?ba  in)
              ?key-id (bytes/read-dynamic-?str in)]
          (asm
            {:kind :encrypted-with-symmetric-key, :version 1}
            :ba-aad ?ba-aad
            :key-id ?key-id))

        :encrypted-with-password-v1
        (let [?ba-aad (bytes/read-dynamic-?ba in)]
          (asm
            {:kind :encrypted-with-password, :version 1}
            :ba-aad ?ba-aad))

        :signed-v1
        (let [?ba-aad     (bytes/read-dynamic-?ba  in)
              key-algo    (df/read-kid             in :key-algo)
              ?key-id     (bytes/read-dynamic-?str in)
              ?ba-content (bytes/read-dynamic-?ba  in)]
          (impl/key-algo! key-algo [:sig-algo])
          (asm
            {:kind :signed, :version 1, :key-algo key-algo}
            :ba-aad     ?ba-aad
            :key-id     ?key-id
            :ba-content ?ba-content))

        (:encrypted-with-1-keypair-simple-v1
         :encrypted-with-1-keypair-hybrid-v1)
        (let [hybrid?  (= env-kid :encrypted-with-1-keypair-hybrid-v1)
              ?ba-aad  (when hybrid? (bytes/read-dynamic-?ba  in))
              key-algo               (df/read-kid             in :key-algo)
              ?key-id                (bytes/read-dynamic-?str in)]
          (impl/key-algo! key-algo [:asym-cipher-algo])
          (asm
            {:kind :encrypted-with-1-keypair, :version 1, :key-algo key-algo}
            :hybrid? (when hybrid? true)
            :ba-aad  ?ba-aad
            :key-id  ?key-id))

        :encrypted-with-2-keypairs-v1
        (let [?ba-aad      (bytes/read-dynamic-?ba  in)
              key-algo     (df/read-kid             in :key-algo)
              ?recp-key-id (bytes/read-dynamic-?str in)
              ?send-key-id (bytes/read-dynamic-?str in)]
          (impl/key-algo! key-algo [:ka-algo])
          (asm
            {:kind :encrypted-with-2-keypairs, :version 1, :key-algo key-algo}
            :ba-aad          ?ba-aad
            :receiver-key-id ?recp-key-id
            :sender-key-id   ?send-key-id))

        :encrypted-keychain-v1
        (let [?ba-aad   (bytes/read-dynamic-?ba in)
              ba-kc-pub (bytes/read-dynamic-ba  in)]
          (asm
            {:kind :encrypted-keychain, :version 1,
             :keychain (keys/keychain-restore ba-kc-pub)}
            :ba-aad ?ba-aad))

        (enc/unexpected-arg! env-kid
          {:expected :envelope-with-public-data
           :context  `public-data})))))

(defn- public-data-test
  [ba-tempel-output]
  (when-let [{:keys [ba-aad ba-content] :as pd} (public-data ba-tempel-output)]
    ;; As with :_test elsewhere
    (enc/assoc-some (dissoc pd :ba-aad :ba-content)
      :aad (bytes/?utf8-ba->?str ba-aad)
      :cnt (bytes/?utf8-ba->?str ba-content))))

;;;; Cipher API

(defn- return-val [context return-kind ?ba-cnt ?ba-aad]
  (case return-kind
    :ba-content ?ba-cnt
    :ba-aad     ?ba-aad
    :as-map
    (enc/assoc-some {}
      :ba-content ?ba-cnt
      :ba-aad     ?ba-aad)

    :_test ; Undocumented, used for tests
    (enc/assoc-some {}
      :aad (bytes/?utf8-ba->?str ?ba-aad)
      :cnt (bytes/?utf8-ba->?str ?ba-cnt))

    (enc/unexpected-arg! return-kind
      {:expected #{:ba-content :ba-aad :as-map}
       :context  context})))

(defn encrypt-with-password
  "Uses a symmetric cipher to encrypt the given byte[] content and return
  a byte[] that includes:
    - The encrypted content
    - Optional unencrypted AAD (see `aad-help` docstring)
    - Envelope data necessary for decryption (specifies algorithms, etc.)

  Takes a password (string, byte[], or char[]).
  Password will be \"stretched\" using an appropriate \"Password-Based Key
  Derivation Function\" (PBKDF).

  Decrypt output with: `decrypt-with-password`.

  Options:
    `:ba-aad` - See `aad-help` docstring
    `:ba-akm` - See `akm-help` dosctring

  Relevant `*config*` keys (see that var's docstring for details):
    `hash-algo`, `sym-cipher-algo`, `pbkdf-algo`, `pbkdf-nwf`, `embed-key-ids?`"

  #_(df/reference-data-formats :encrypted-with-password-v1)
  ^bytes
  [ba-content password &
   [{:keys [ba-aad ba-akm, :config
            hash-algo sym-cipher-algo
            pbkdf-algo pbkdf-nwf
            embed-key-ids?]}]]

  (let [{:keys [hash-algo sym-cipher-algo pbkdf-algo pbkdf-nwf
                embed-key-ids?]} (get-config config)
        _ (have? some? hash-algo sym-cipher-algo pbkdf-algo pbkdf-nwf)

        sck        (impl/as-symmetric-cipher-kit sym-cipher-algo)
        key-len    (impl/sck-key-len sck)

        ba-iv      (impl/rand-ba (max 16 (impl/sck-iv-len sck)))
        ba-salt    (impl/hmac hash-algo ba-iv (bytes/str->utf8-ba "iv->salt"))

        pbkdf-nwf  (pbkdf/pbkdf-nwf-parse pbkdf-algo pbkdf-nwf)
        ba-key     (let [ba-pkey (pbkdf/pbkdf pbkdf-algo key-len ba-salt password pbkdf-nwf)]
                     (impl/hmac hash-algo ba-pkey ba-akm))

        ba-ecnt    (impl/sck-encrypt sck ba-iv ba-key ba-content ba-aad)]

    (bytes/with-out [out] [24 ba-ecnt ba-aad ba-iv]
      (df/write-head          out)
      (df/write-kid           out :envelope :encrypted-with-password-v1)
      (bytes/write-dynamic-ba out ba-aad)
      (df/write-kid           out :hash-algo       hash-algo)
      (df/write-kid           out :sym-cipher-algo sym-cipher-algo)
      (df/write-kid           out :pbkdf-algo pbkdf-algo)
      (bytes/write-ushort     out             pbkdf-nwf)
      (bytes/write-dynamic-ba out nil #_ba-salt)
      (bytes/write-dynamic-ba out ba-iv)
      (bytes/write-dynamic-ba out ba-ecnt)
      (df/write-resv          out))))

(comment (public-data-test (encrypt-with-password (as-ba "cnt") "pwd")))

(defn decrypt-with-password
  "Complement of `encrypt-with-password`.

  Uses a symmetric cipher to decrypt the given byte[].
  Return value depends on `:return` option:
    `:ba-content` - Returns decrypted byte[] content (default)
    `:ba-aad`     - Returns verified unencrypted embedded ?byte[] AAD
    `:as-map`     - Returns {:keys [ba-aad ba-content]} map

  Takes a password (string, byte[], or char[]). Password will be \"stretched\"
  using an appropriate \"Password-Based Key Derivation Function\" (PBKDF).

  Will throw on decryption failure (bad password, etc.)."

  #_(df/reference-data-formats :encrypted-with-password-v1)
  [ba-encrypted password &
   [{:keys [return ba-akm]
     :or   {return :ba-content}}]]

  (bytes/with-in [in] ba-encrypted
    (let [env-kid         :encrypted-with-password-v1
          _               (df/read-head!          in)
          _               (df/read-kid            in :envelope env-kid)
          ?ba-aad         (bytes/read-dynamic-?ba in)
          hash-algo       (df/read-kid            in :hash-algo)
          sym-cipher-algo (df/read-kid            in :sym-cipher-algo)
          pbkdf-algo      (df/read-kid            in :pbkdf-algo)
          pbkdf-nwf       (bytes/read-ushort      in)
          ?ba-salt        (bytes/read-dynamic-?ba in)
          ba-iv           (bytes/read-dynamic-ba  in)
          ba-ecnt         (bytes/read-dynamic-ba  in)
          _               (df/read-resv!          in)

          sck (impl/as-symmetric-cipher-kit sym-cipher-algo)
          ba-key
          (let [key-len (impl/sck-key-len sck)
                ba-salt (or ?ba-salt (impl/hmac hash-algo ba-iv (bytes/str->utf8-ba "iv->salt")))
                ba-pkey (pbkdf/pbkdf pbkdf-algo key-len ba-salt password pbkdf-nwf)]

            (impl/hmac hash-algo ba-pkey ba-akm))

          ba-cnt
          (try
            (impl/sck-decrypt sck ba-iv ba-key ba-ecnt ?ba-aad)
            (catch Throwable t
              (keys/decrypt-failed!
                (ex-info "Failed to decrypt Tempel data (with password)" {} t))))]

      (return-val env-kid return ba-cnt ?ba-aad))))

(comment
  (let [ba-enc (encrypt-with-password (as-ba "cnt") "pwd")]
    (decrypt-with-password ba-enc "pwd" {:return :_test})))

(defn encrypt-with-symmetric-key
  "Uses a symmetric cipher to encrypt the given byte[] content and return
  a byte[] that includes:
    - The encrypted content
    - Optional unencrypted AAD (see `aad-help` docstring)
    - Envelope data necessary for decryption (specifies algorithms, etc.)

  Takes a `KeyChain` (see `keychain`) or byte[] key.
  Decrypt output with: `decrypt-with-symmetric-key`.

  Options:
    `:ba-aad` - See `aad-help` docstring
    `:ba-akm` - See `akm-help` docstring

  Relevant `*config*` keys (see that var's docstring for details):
    `hash-algo`, `sym-cipher-algo`, `embed-key-ids?`"

  #_(df/reference-data-formats :encrypted-with-symmetric-key-v1)
  ^bytes
  [ba-content key-sym &
   [{:keys [ba-aad ba-akm, :config
            hash-algo sym-cipher-algo embed-key-ids?] :as opts}]]

  (let [{:keys [hash-algo sym-cipher-algo embed-key-ids?]} (get-config opts)
        _ (have? some? hash-algo sym-cipher-algo)

        ckey-sym (keys/get-ckeys-sym-cipher key-sym)
        {:keys [key-sym key-id]} @ckey-sym
        ba-key     (have enc/bytes? key-sym)
        ?ba-key-id (when embed-key-ids? (bytes/?str->?utf8-ba key-id))

        sck     (impl/as-symmetric-cipher-kit sym-cipher-algo)
        ba-iv   (impl/rand-ba (impl/sck-iv-len sck))
        ba-key* (impl/hmac hash-algo ba-key ba-akm ba-iv) ; +IV for forward secrecy
        ba-ecnt (impl/sck-encrypt sck ba-iv ba-key* ba-content ba-aad)]

    (bytes/with-out [out] [16 ba-ecnt ba-aad ?ba-key-id ba-iv]
      (df/write-head          out)
      (df/write-kid           out :envelope :encrypted-with-symmetric-key-v1)
      (bytes/write-dynamic-ba out ba-aad)
      (bytes/write-dynamic-ba out ?ba-key-id)
      (df/write-kid           out :hash-algo       hash-algo)
      (df/write-kid           out :sym-cipher-algo sym-cipher-algo)
      (bytes/write-dynamic-ba out ba-iv)
      (bytes/write-dynamic-ba out ba-ecnt)
      (df/write-resv          out))))

(comment (public-data-test (encrypt-with-symmetric-key (as-ba "cnt") (keychain))))

(defn decrypt-with-symmetric-key
  "Complement of `encrypt-with-symmetric-key`.

  Uses a symmetric cipher to decrypt the given byte[].
  Return value depends on `:return` option:
    `:ba-content` - Returns decrypted byte[] content (default)
    `:ba-aad`     - Returns verified unencrypted embedded ?byte[] AAD
    `:as-map`     - Returns {:keys [ba-aad ba-content]} map

  Takes a `KeyChain` (see `keychain`) or byte[] key.
  Will throw on decryption failure (bad key, etc.)."

  #_(df/reference-data-formats :encrypted-with-symmetric-key-v1)
  [ba-encrypted key-sym &
   [{:keys [return ba-akm]
     :or   {return :ba-content}}]]

  (bytes/with-in [in] ba-encrypted
    (let [env-kid         :encrypted-with-symmetric-key-v1
          _               (df/read-head!           in)
          _               (df/read-kid             in :envelope env-kid)
          ?ba-aad         (bytes/read-dynamic-?ba  in)
          ?key-id         (bytes/read-dynamic-?str in)
          hash-algo       (df/read-kid             in :hash-algo)
          sym-cipher-algo (df/read-kid             in :sym-cipher-algo)
          ba-iv           (bytes/read-dynamic-ba   in)
          ba-ecnt         (bytes/read-dynamic-ba   in)
          _               (df/read-resv!           in)

          sck       (impl/as-symmetric-cipher-kit sym-cipher-algo)
          ckeys-sym (keys/get-ckeys-sym-cipher key-sym ?key-id)
          ba-cnt
          (keys/try-decrypt-with-keys! `decrypt-with-symmetric-key
            (some? ?key-id) ckeys-sym
            (fn [ckey-sym]
              (let [{:keys [key-sym]} @ckey-sym
                    ba-key  (have enc/bytes? key-sym)
                    ba-key* (impl/hmac hash-algo ba-key ba-akm ba-iv) ; +IV for forward secrecy
                    ba-cnt  (impl/sck-decrypt sck ba-iv ba-key* ba-ecnt ?ba-aad)]
                ba-cnt)))]

      (return-val env-kid return ba-cnt ?ba-aad))))

(comment
  (let [kc     (keychain)
        ba-enc (encrypt-with-symmetric-key (as-ba "cnt") kc)]
    (decrypt-with-symmetric-key ba-enc kc {:return :_test})))

(defn encrypt-with-1-keypair
  "Uses a symmetric or hybrid (symmetric + asymmetric) scheme to encrypt the
  given content byte[] and return a byte[] that includes:
    - The encrypted content
    - Optional unencrypted AAD (see `aad-help` docstring)
    - Envelope data necessary for decryption (specifies algorithms, etc.)

  Takes a `KeyChain` (see `keychain`) or `KeyPair` (see `keypair-create`).
  Key algorithm must support use as an asymmetric cipher.
  Suitable algorithms: `:rsa-<nbits>`

  Encryption uses receiver's asymmetric public  key.
  Decryption uses receiver's asymmetric private key.

  Decrypt output byte[] with: `decrypt-with-1-keypair`.

  Options:
    `:ba-aad` - See `aad-help` docstring
    `:ba-akm` - See `akm-help` docstring

  Relevant `*config*` keys (see that var's docstring for details):
    `hash-algo`, `sym-cipher-algo`, `asym-cipher-algo`, `embed-key-ids`?"

  ^bytes
  [ba-content receiver-key-pub &
   [{:keys [ba-aad ba-akm, :config
            hash-algo sym-cipher-algo asym-cipher-algo
            embed-key-ids?] :as opts}]]

  (let [{:keys [asym-cipher-algo embed-key-ids?] :as opts*}
        (get-config opts)

        ckey-pub (keys/get-ckeys-asym-cipher receiver-key-pub)
        {:keys [key-pub key-id key-algo]} @ckey-pub

        ?ba-key-id       (when embed-key-ids? (bytes/?str->?utf8-ba key-id))
        asym-cipher-algo (have (or asym-cipher-algo (get (impl/key-algo-info key-algo) :asym-cipher-algo)))

        ;; Simple optimization to cover ~common case of encrypting symmetric keys
        hybrid? (or ba-aad ba-akm (> (alength ^bytes ba-content) 64))]

    (if hybrid?

      ;; Hybrid scheme:
      ;;   - Use a random 1-time symmetric key to encrypt content
      ;;   - Wrap symmetric key with asymmetric encryption, embed

      #_(df/reference-data-formats :encrypted-with-1-keypair-hybrid-v1)
      (let [{:keys [hash-algo sym-cipher-algo]} opts*
            _ (have? some? hash-algo sym-cipher-algo)

            sck             (impl/as-symmetric-cipher-kit sym-cipher-algo)
            ba-iv           (impl/rand-ba (impl/sck-iv-len  sck))
            ba-key-pre-akm  (impl/rand-ba (impl/sck-key-len sck)) ; Random symmetric key (=> forward secrecy)
            ba-key-post-akm (impl/hmac hash-algo ba-key-pre-akm ba-akm)
            ba-ecnt         (impl/sck-encrypt sck ba-iv ba-key-post-akm ba-content ba-aad)
            ba-ekey         (impl/encrypt-asymmetric asym-cipher-algo
                              key-algo key-pub ba-key-pre-akm)]

        #_(df/reference-data-formats :encrypted-with-1-keypair-simple-v1)
        (bytes/with-out [out] [24 ba-ecnt ba-aad ba-iv ba-ekey]
          (df/write-head          out)
          (df/write-kid           out :envelope :encrypted-with-1-keypair-hybrid-v1)
          (bytes/write-dynamic-ba out ba-aad)
          (df/write-kid           out :key-algo key-algo)
          (bytes/write-dynamic-ba out ?ba-key-id)
          (df/write-kid           out :hash-algo        hash-algo)
          (df/write-kid           out :sym-cipher-algo  sym-cipher-algo)
          (df/write-kid           out :asym-cipher-algo asym-cipher-algo)
          (bytes/write-dynamic-ba out ba-iv)
          (bytes/write-dynamic-ba out ba-ecnt)
          (bytes/write-dynamic-ba out ba-ekey)
          (df/write-resv          out)))

      (let [ba-ecnt (impl/encrypt-asymmetric asym-cipher-algo key-algo key-pub ba-content)]
        (bytes/with-out [out] [24 ba-ecnt]
          (df/write-head             out)
          (df/write-kid              out :envelope :encrypted-with-1-keypair-simple-v1)
          ;; (bytes/write-dynamic-ba out ba-aad
          (df/write-kid              out :key-algo key-algo)
          (bytes/write-dynamic-ba    out ?ba-key-id)
          ;; (df/write-kid           out :hash-algo        hash-algo)
          ;; (df/write-kid           out :sym-cipher-algo  sym-cipher-algo)
          (df/write-kid              out :asym-cipher-algo asym-cipher-algo)
          ;; (bytes/write-dynamic-ba out ba-iv)
          (bytes/write-dynamic-ba    out ba-ecnt)
          ;; (bytes/write-dynamic-ba out ba-ekey)
          (df/write-resv             out))))))

(comment
  [(public-data-test (encrypt-with-1-keypair (impl/rand-ba 32)  (keychain)))
   (public-data-test (encrypt-with-1-keypair (impl/rand-ba 128) (keychain)))])

(defn decrypt-with-1-keypair
  "Complement of `encrypt-with-1-keypair`.

  Uses a hybrid (symmetric + asymmetric) scheme to decrypt the given byte[].
  Return value depends on `:return` option:
    `:ba-content` - Returns decrypted byte[] content (default)
    `:ba-aad`     - Returns verified unencrypted embedded ?byte[] AAD
    `:as-map`     - Returns {:keys [ba-aad ba-content]} map

  Takes a `KeyChain` (see `keychain`) or `KeyPair` (see `keypair-create`).
  Key algorithm must support use as an asymmetric cipher.
  Suitable algorithms: `:rsa-<nbits>`

  Encryption uses receiver's asymmetric public  key.
  Decryption uses receiver's asymmetric private key.

  Will throw on decryption failure (bad key, etc.)."

  [ba-encrypted receiver-key-prv &
   [{:keys [return ba-akm]
     :or   {return :ba-content}}]]

  (bytes/with-in [in] ba-encrypted
    (let [_        (df/read-head! in)
          env-kid  (df/read-kid   in :envelope
                     #{:encrypted-with-1-keypair-hybrid-v1
                       :encrypted-with-1-keypair-simple-v1})]

      (case env-kid
        :encrypted-with-1-keypair-hybrid-v1
        #_(df/reference-data-formats :encrypted-with-1-keypair-hybrid-v1)
        (let [?ba-aad          (bytes/read-dynamic-?ba  in)
              key-algo         (df/read-kid             in :key-algo)
              ?key-id          (bytes/read-dynamic-?str in)
              hash-algo        (df/read-kid             in :hash-algo)
              sym-cipher-algo  (df/read-kid             in :sym-cipher-algo)
              asym-cipher-algo (df/read-kid             in :asym-cipher-algo)
              ba-iv            (bytes/read-dynamic-ba   in)
              ba-ecnt          (bytes/read-dynamic-ba   in)
              ba-ekey          (bytes/read-dynamic-ba   in)
              _                (df/read-resv!           in)

              sck       (impl/as-symmetric-cipher-kit sym-cipher-algo)
              ckeys-prv (keys/get-ckeys-asym-cipher receiver-key-prv key-algo ?key-id)
              ba-cnt
              (keys/try-decrypt-with-keys! `decrypt-with-1-keypair
                (some? ?key-id) ckeys-prv
                (fn [ckey-prv]
                  (let [{:keys [key-prv]} @ckey-prv
                        ba-key-pre-akm  (impl/decrypt-asymmetric asym-cipher-algo
                                          key-algo key-prv ba-ekey) ; Symmetric key
                        ba-key-post-akm (impl/hmac hash-algo ba-key-pre-akm ba-akm)
                        ba-cnt (impl/sck-decrypt sck ba-iv ba-key-post-akm ba-ecnt ?ba-aad)]
                    ba-cnt)))]

          (return-val env-kid return ba-cnt ?ba-aad))

        :encrypted-with-1-keypair-simple-v1
        #_(df/reference-data-formats :encrypted-with-1-keypair-simple-v1)
        (let [;; ?ba-aad         (bytes/read-dynamic-?ba  in)
              key-algo           (df/read-kid             in :key-algo)
              ?key-id            (bytes/read-dynamic-?str in)
              ;; hash-algo       (df/read-kid             in :hash-algo)
              ;; sym-cipher-algo (df/read-kid             in :sym-cipher-algo)
              asym-cipher-algo   (df/read-kid             in :asym-cipher-algo)
              ;; ba-iv           (bytes/read-dynamic-ba   in)
              ba-ecnt            (bytes/read-dynamic-ba   in)
              ;; ba-ekey         (bytes/read-dynamic-ba   in)
              _                  (df/read-resv!           in)

              ckeys-prv (keys/get-ckeys-asym-cipher receiver-key-prv key-algo ?key-id)
              ba-cnt
              (keys/try-decrypt-with-keys! `decrypt-with-1-keypair
                (some? ?key-id) ckeys-prv
                (fn [ckey-prv]
                  (let [{:keys [key-prv]} @ckey-prv
                        ba-cnt (impl/decrypt-asymmetric asym-cipher-algo key-algo key-prv ba-ecnt)]
                    ba-cnt)))]

          (return-val env-kid return ba-cnt nil))

        (enc/unexpected-arg! env-kid
          {:context `decrypt-with-1-keypair
           :expected
           #{:encrypted-with-1-keypair-hybrid-v1
             :encrypted-with-1-keypair-simple-v1}})))))

(comment
  (let [kc     (keychain)
        ba-enc (encrypt-with-1-keypair (as-ba "cnt") kc)]
    (decrypt-with-1-keypair ba-enc kc {:return :_test})))

(defn encrypt-with-2-keypairs
  "Uses a hybrid (symmetric + asymmetric) scheme to encrypt the given content
  byte[] and return a byte[] that includes:
    - The encrypted content
    - Optional unencrypted AAD (see `aad-help` docstring)
    - Envelope data necessary for decryption (specifies algorithms, etc.)

  Takes `KeyChain`s (see `keychain`) and/or `KeyPair`s (see `keypair-create`).
  Key algorithm must support key agreement.
  Suitable algorithms: `:dh-<nbits>`, `:ec-<curve>`

  Encryption uses:
    - Receiver's asymmetric public  key
    - Sender's   asymmetric private key

  Decryption uses:
    - Receiver's asymmetric private key
    - Sender's   asymmetric public  key

  Decrypt output byte[] with: `decrypt-with-2-keypairs`.

  Options:
    `:ba-aad` - See `aad-help` docstring
    `:ba-akm` - See `akm-help` docstring

  Relevant `*config*` keys (see that var's docstring for details):
    `hash-algo`, `ka-algo`, `sym-cipher-algo`, `embed-key-ids?`"

  #_(df/reference-data-formats :encrypted-with-2-keypairs-v1)
  ^bytes
  [ba-content receiver-key-pub sender-key-prv &
   [{:keys [ba-aad ba-akm, :config
            hash-algo ka-algo sym-cipher-algo embed-key-ids?] :as opts}]]

  ;; Hybrid scheme:
  ;;   - Gen symmetric key via key agreement
  ;;   - Use symmetric key to encrypt content

  ;; Ref. NIST SP 800-56A §5.9.1 to §5.9.3. for SKM/AKM

  (let [{:keys [hash-algo ka-algo sym-cipher-algo embed-key-ids?]} (get-config opts)
        _ (have? some? hash-algo sym-cipher-algo)

        [recvr-ckey-pub sendr-ckey-prv] (keys/get-ckeys-ka receiver-key-pub sender-key-prv)
        {:keys [key-pub         ], recvr-key-id :key-id} @recvr-ckey-pub
        {:keys [key-prv key-algo], sendr-key-id :key-id} @sendr-ckey-prv

        ?ba-recvr-key-id (when embed-key-ids? (bytes/?str->?utf8-ba recvr-key-id))
        ?ba-sendr-key-id (when embed-key-ids? (bytes/?str->?utf8-ba sendr-key-id))

        ka-algo (have (or ka-algo (get (impl/key-algo-info key-algo) :ka-algo)))
        sck     (impl/as-symmetric-cipher-kit sym-cipher-algo)
        ba-iv   (impl/rand-ba (impl/sck-iv-len sck))
        ba-key
        (let [ba-shared-key (impl/key-shared-create ka-algo key-algo key-prv key-pub)]
          (impl/hmac hash-algo ba-shared-key ba-akm ba-iv)) ; +IV for forward secrecy

        ba-ecnt (impl/sck-encrypt sck ba-iv ba-key ba-content ba-aad)]

    (bytes/with-out [out] [16 ba-ecnt ba-aad ?ba-recvr-key-id ?ba-sendr-key-id ba-iv]
      (df/write-head          out)
      (df/write-kid           out :envelope :encrypted-with-2-keypairs-v1)
      (bytes/write-dynamic-ba out ba-aad)
      (df/write-kid           out :key-algo key-algo)
      (bytes/write-dynamic-ba out ?ba-recvr-key-id)
      (bytes/write-dynamic-ba out ?ba-sendr-key-id)
      (df/write-kid           out :hash-algo       hash-algo)
      (df/write-kid           out :ka-algo         ka-algo)
      (df/write-kid           out :sym-cipher-algo sym-cipher-algo)
      (bytes/write-dynamic-ba out ba-iv)
      (bytes/write-dynamic-ba out ba-ecnt)
      (df/write-resv          out))))

(comment (public-data-test (encrypt-with-2-keypairs (as-ba "cnt") (keychain) (keychain))))

(defn decrypt-with-2-keypairs
  "Complement of `encrypt-with-2-keypairs`.

  Uses a hybrid (symmetric + asymmetric) scheme to decrypt the given byte[].
  Return value depends on `:return` option:
    `:ba-content` - Returns decrypted byte[] content (default)
    `:ba-aad`     - Returns verified unencrypted embedded ?byte[] AAD
    `:as-map`     - Returns {:keys [ba-aad ba-content]} map

  Takes `KeyChain`s (see `keychain`) and/or `KeyPair`s (see `keypair-create`).
  Key algorithm must support key agreement.
  Suitable algorithms: `:dh-<nbits>`, `:ec-<curve>`

  Encryption uses:
    - Receiver's asymmetric public  key
    - Sender's   asymmetric private key

  Decryption uses:
    - Receiver's asymmetric private key
    - Sender's   asymmetric public  key

  Will throw on decryption failure (bad key, etc.)."

  #_(df/reference-data-formats :encrypted-with-2-keypairs-v1)
  [ba-encrypted receiver-key-prv sender-key-pub &
   [{:keys [return ba-akm]
     :or   {return :ba-content}}]]

  (bytes/with-in [in] ba-encrypted
    (let [env-kid         :encrypted-with-2-keypairs-v1
          _               (df/read-head!           in)
          _               (df/read-kid             in :envelope env-kid)
          ?ba-aad         (bytes/read-dynamic-?ba  in)
          key-algo        (df/read-kid             in :key-algo)
          ?recvr-key-id   (bytes/read-dynamic-?str in)
          ?sendr-key-id   (bytes/read-dynamic-?str in)

          hash-algo       (df/read-kid             in :hash-algo)
          ka-algo         (df/read-kid             in :ka-algo)
          sym-cipher-algo (df/read-kid             in :sym-cipher-algo)
          ba-iv           (bytes/read-dynamic-ba   in)
          ba-ecnt         (bytes/read-dynamic-ba   in)
          _               (df/read-resv!           in)

          sck             (impl/as-symmetric-cipher-kit sym-cipher-algo)

          ckey-pairs ; [[<recvr-ckey-prv> <sendr-ckey-pub>] ...]
          (keys/get-ckeys-ka key-algo
            [receiver-key-prv ?recvr-key-id]
            [sender-key-pub   ?sendr-key-id])

          ba-cnt
          (keys/try-decrypt-with-keys! `decrypt-with-2-keypairs
            (some? ?recvr-key-id) ckey-pairs
            (fn [[recvr-ckey-prv sendr-ckey-pub]]
              (let [{:keys [key-prv]} @recvr-ckey-prv
                    {:keys [key-pub]} @sendr-ckey-pub

                    ba-key
                    (let [ba-shared-key (impl/key-shared-create ka-algo key-algo key-prv key-pub)]
                      (impl/hmac hash-algo ba-shared-key ba-akm ba-iv))

                    ba-cnt (impl/sck-decrypt sck ba-iv ba-key ba-ecnt ?ba-aad)]

                ba-cnt)))]

      (return-val env-kid return ba-cnt ?ba-aad))))

(comment
  (let [kc1    (keychain)
        kc2    (keychain)
        ba-enc (encrypt-with-2-keypairs (as-ba "cnt") kc1 kc2)]
    (decrypt-with-2-keypairs ba-enc kc1 kc2 {:return :_test})))

;;;; Signature API

(defn sign
  "Cryptographically signs the given content byte[] and returns a byte[]
  that includes:
    - Optional unencrypted content (see `embed-content?` option below)
    - Optional unencrypted AAD     (see `aad-help` docstring)
    - Envelope data necessary for verification (specifies algorithms, etc.)

  Basically produces:
    - Signed content when `embed-content?` is true (default)
    - A signature    when `embed-content?` is false

  Takes a `KeyChain` (see `keychain`) or `KeyPair` (see `keypair-create`).
  Key algorithm must support signatures.
  Suitable algorithms: `:rsa-<nbits>`, `:ec-<curve>`

  Signing      uses signer's asymmetric private key.
  Verification uses signer's asymmetric public  key.

  Verify with: `signed`.

  Relevant `*config*` keys (see that var's docstring for details):
    `hash-algo`, `sig-algo`, `embed-key-ids?`"

  #_(df/reference-data-formats :signed-v1)
  ^bytes
  [ba-content signer-key-prv &
   [{:keys [ba-aad ba-akm embed-content?, :config
            hash-algo sig-algo embed-key-ids?]
     :as opts
     :or {embed-content? true}}]]

  (let [{:keys [hash-algo sig-algo embed-key-ids?]} (get-config opts)
        _ (have? some? hash-algo)

        ckey-prv (keys/get-ckeys-sig signer-key-prv)
        {:keys [key-prv key-id key-algo]} @ckey-prv
        ?ba-key-id (when embed-key-ids? (bytes/?str->?utf8-ba key-id))
        ?ba-em-cnt (when embed-content? ba-content)

        sig-algo   (have (or sig-algo (get (impl/key-algo-info key-algo) :sig-algo)))
        ba-to-sign (impl/hash-ba-cascade hash-algo ba-content ba-akm ba-aad)
        ba-sig     (impl/signature-create sig-algo key-algo key-prv ba-to-sign)]

    (bytes/with-out [out] [8 ba-aad ?ba-key-id ba-sig ?ba-em-cnt]
      (df/write-head          out)
      (df/write-kid           out :envelope :signed-v1)
      (bytes/write-dynamic-ba out ba-aad)
      (df/write-kid           out :key-algo key-algo)
      (bytes/write-dynamic-ba out ?ba-key-id)
      (bytes/write-dynamic-ba out ?ba-em-cnt)
      (df/write-kid           out :hash-algo hash-algo)
      (df/write-kid           out :sig-algo  sig-algo)
      (bytes/write-dynamic-ba out ba-sig)
      (df/write-resv          out))))

(comment (public-data-test (sign (as-ba "cnt") (keychain))))

(defn signed
  "Complement of `sign`.

  Cryptographically verifies if the given signed byte[] was signed by the
  private key corresponding to the given public key.

  Return value depends on `:return` option:
    `:ba-content` - Returns verified ?byte[] content (when embedded)
    `:ba-aad`     - Returns verified ?byte[] AAD     (when embedded)
    `:as-map`     - Returns {:keys [ba-aad ba-content]} map (default)

  Returns nil when verification fails.

  Takes a `KeyChain` (see `keychain`) or `KeyPair` (see `keypair-create`).
  Key algorithm must support signatures.
  Suitable algorithms: `:rsa-<nbits>`, `:ec-<curve>`

  Signing      uses signer's asymmetric private key.
  Verification uses signer's asymmetric public  key."

  #_(df/reference-data-formats :signature-v1)
  [ba-signed signer-key-pub &
   [{:keys [return ba-content ba-akm]
     :or   {return :as-map}}]]

  (bytes/with-in [in] ba-signed
    (let [env-kid    :signed-v1
          _          (df/read-head!           in)
          _          (df/read-kid             in :envelope env-kid)
          ?ba-aad    (bytes/read-dynamic-?ba  in)
          key-algo   (df/read-kid             in :key-algo)
          ?key-id    (bytes/read-dynamic-?str in)
          ?ba-em-cnt (bytes/read-dynamic-?ba  in)
          hash-algo  (df/read-kid             in :hash-algo)
          sig-algo   (df/read-kid             in :sig-algo)
          ba-sig     (bytes/read-dynamic-ba   in)
          _          (df/read-resv!           in)

          ba-cnt     (or ba-content ?ba-em-cnt)
          ckeys-pub  (keys/get-ckeys-sig signer-key-pub key-algo ?key-id)
          ba-to-sign (impl/hash-ba-cascade hash-algo ba-cnt ba-akm ?ba-aad)

          {:keys [success _error _errors]}
          (keys/try-keys (some? ?key-id) ckeys-pub
            (fn [ckey-pub]
              (let [{:keys [key-pub]} @ckey-pub]
                (if (impl/signature-verify sig-algo key-algo key-pub ba-to-sign ba-sig)
                  {:ba-content ba-cnt
                   :ba-aad     ?ba-aad}))))]

      (when-let [{:keys [ba-content ba-aad]} success]
        (return-val `signed return ba-content ba-aad)))))

(comment
  (let [kc        (keychain)
        ba-signed (sign (as-ba "cnt") kc {:ba-aad (as-ba "aad")})]
    (signed ba-signed kc {:return :as-map #_:_test})))
