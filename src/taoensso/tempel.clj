(ns taoensso.tempel
  "Data security framework for Clojure.

  See the GitHub page (esp. Wiki) for info on motivation and design:
    <https://www.taoensso.com/tempel>

  See `df.clj` for data formats.
  All formats intended to support non-breaking future updates.

  Abbreviations:
    External:
      pbkdf - Password Based Key Derivation Function
      aad   - Additional Associated Aata (see `help:aad`)
      akm   - Additional Keying Material (see `help:akm`)
      kek   - Key encryption key (key used to encrypt another key)
      cnt   - Unencrypted content
      ecnt  - Encrypted   content
      kc    - KeyChain
      ck    - ChainKey

    Internal:
        key0  - Rand/user/password key (pre AKM, etc.)
        key1  - Key with AKM, etc.
        key2  - Final key ready for encryption/decryption
        key1b - Backup    key
       ekeyX  - Encrypted key"

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

(enc/assert-min-encore-version [3 95 1])

;;;; TODO
;; - Consider including something like Signal's "Double Ratchet" work?
;;   - X3DH ("Extended Triple Diffie-Hellman") key agreement protocol, Ref. <https://signal.org/docs/specifications/x3dh/>
;;     - Provides forward secrecy and cryptographic deniability.
;;     - Users have:
;;       - 1x permanent identity keypair, replaced only if private key is lost, pub on server
;;       - nx one-time "pre-key" keypairs, signed by identkey, updated regularly (e.g. weekly), sigs on server
;;   - "Double Ratchet" message protocol, Ref. <https://www.signal.org/docs/specifications/doubleratchet/>
;;     - Uses unique key for each message in conversation.
;;     - Keys generated such that a leaked key for msg n leaves other
;;       (earlier + later) keys ~secure.

;;;; Aliases

(enc/defaliases
  enc/str->utf8-ba
  enc/utf8-ba->str
  enc/rate-limiter
  enc/ba=
  bytes/as-ba
  impl/rand-ba

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

  {:alias encrypt-keychain, :src keychain-encrypt, #_:doc #_"Alias for `keychain-encrypt`"}
  {:alias decrypt-keychain, :src keychain-decrypt, #_:doc #_"Alias for `keychain-decrypt`"})

;;;; Doc vars

(def help:aad
  "\"Additional Authenticated Data\" (AAD) is optional arbitrary byte[] data that
  may be provided to many of Tempel's API functions (e.g. `encrypt-with-X` when
  using an AEAD cipher).

  When provided, AAD will be embedded *UNENCRYPTED* with the API function's
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
    - Arbitrary Clojure data via Nippy, Ref. <https://www.taoensso.com/nippy>"

  "See docstring")

(def help:akm
  "\"Additional Keying Material\" (AKM) is optional arbitrary byte[] data that
  may be provided to many of Tempel's API functions (e.g. `encrypt-with-X`).

  When provided, AKM will act as additional secret material to supplement any
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
    - Arbitrary Clojure data via Nippy, Ref. <https://www.taoensso.com/nippy>"

  ;; Ref. NIST SP 800-56A §5.9.1 to §5.9.3 for SKM/AKM

  "See docstring")

;;;; Config

(enc/defonce default-keypair-creator_
  "Default stateful `KeyPair` generator with options:
  {:buffer-len 16, :n-threads [:perc 10]}"
  (delay (impl/keypair-creator {:buffer-len 16, :n-threads [:ratio 0.1]})))

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

   :embed-key-ids?      true
   :embed-hmac?         true
   :ignore-hmac?        false

   :backup-key          nil
   :backup-opts         nil})

(enc/defonce ^:dynamic *config*
  "Tempel's behaviour is controlled by:
    1. Call   options, as provided to API functions.
    2. Config options, as provided in this dynamic map.

  Config options (2) act as the default over which call options (1) will be merged.
  So these are equivalent:

    (binding [*config* <your-opts>)]
      (encrypt-with-password ba-content password {}))

    (encrypt-with-password ba-content password <your-opts>)

  Config options:

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
      time on a 2020 M1 Macbook Pro. See `pbkdf-nwf-estimate`.

      Default: `:ref-100-msecs`, a reasonable value for many logins.

    `:sym-cipher-algo` ∈ #{*:aes-gcm-128-v1 :aes-gcm-256-v1 :chacha20-poly1305-v1}
      The symmetric cipher algorithm to use. A cipher that supports \"AEAD\"
      (Authenticated Encryption with Associated Data) must generally be provided
      in order to use `:ba-aad` options (see `help:aad`).

      Default: `:aes-gcm-128-v1`, a good general-purpose symmetric cipher with
      AEAD support.

      Note that the 256 bit AES cipher is not necessarily stronger than the 128
      bit, and may even be weaker due to possible unique attack vectors
      (Ref. <https://goo.gl/qU4CCV>).

    `:keypair-creator` ∈ #{<function> <delay>}
      The function to use when generating asymmetric keypairs.
      See `keypair-create`, `keypair-creator` for details.

      Default: `default-keypair-creator_`, which uses up to 10% of threads
      to buffer up to 16 keypairs per type.

      This is often something you'll want to customize.

    `:symmetric-keys`
      Symmetric keys to add to new `KeyChain`s.
      See `keychain` for details.

      Default: a single random symmetric key.

    `:asymmetric-keypairs`
      Asymmetric keypairs to add to new `KeyChain`s.
      See `keychain` for details.

      Default:
        - A single new `:rsa-3072` keypair, and
        - A single new `:dh-3072`  keypair

      Together these support all common Tempel functionality, and are a
      reasonable choice in most cases.

    `:embed-key-ids?` (relevant only when encrypting)
      Should key ids be embedded in encrypted output when using `KeyChain`s?
      This will allow the automatic selection of relevant keys during decryption,
      in exchange for leaking (making public) the ids used for encryption.

      This is often convenient, and *usually* safe unless you have custom key ids
      that contain private information and/or if it's important that you not leak
      information about which public `KeyChain`s might contain the necessary keys.

      Default: true.
      You may want to disable this for maximum security, but note that doing so
      may complicate decryption. See the Tempel Wiki for details.

    `:embed-hmac?` (relevant only when encrypting)
      Should an HMAC be embedded in encrypted output? When present, embedded
      HMACs can be checked on decryption to help verify data integrity and
      decryption key.

      Default: true.
      You'll generally want to keep this enabled unless you're trying to
      minimize the size of your encrypted output. Adds ~32 bytes to output when
      using the default `:sha-256` hash algorithm.

    `:ignore-hmac?` (relevant only when decrypting)
      Should embedded HMAC be ignored when decrypting?

      Default: false.
      Keep this disabled unless you're sure you understand the implications.

    `:backup-key`
      When encrypting:
        Encrypt data so that decryption will be possible with either the primary
        key/password, *OR* with this optional secondary (backup) `KeyChain`
        (see `keychain`) or `KeyPair` (see `keypair-create`).

        NB: this backup key will be able to decrypt *without* AKM (see `help:akm`).

      When decrypting:
        When data was encrypted with support for a backup key, use this
        `KeyChain` (see `keychain`) or `KeyPair` (see `keypair-create`) to decrypt.

      Key algorithm must support use as an asymmetric cipher.
      Suitable algorithms: `:rsa-<nbits>`.

    `:backup-opts`
      When encrypting: encryption opts map used with `:backup-key`.
      When decrypting: decryption opts map used with `:backup-key`."

  default-config)

(defn ^:no-doc get-opts+
  "Implementation detail."
  ([     opts] (enc/fast-merge *config* opts))
  ([base opts] (enc/fast-merge base     opts)))

(comment (get-opts+ {} {:a :A}))

;;;; Misc utils

(defn with-min-runtime*
  "Executes (f) and ensures that at least the given number of milliseconds
  have elapsed before returning result. Can be useful for protection against
  timing attacks, etc.:
    (with-min-runtime* 2000 (fn variable-time-fn [] <...>))"
  [msecs f]
  (let [t0 (System/currentTimeMillis)
        {:keys [okay error]} (try {:okay (f)} (catch Throwable t {:error t}))
        msecs-elapsed (- (System/currentTimeMillis) t0)
        msecs-delta   (- (int msecs) msecs-elapsed)]

    (when (pos? msecs-delta) (Thread/sleep (int msecs-delta)))
    (if error (throw error) okay)))

(defmacro with-min-runtime
  "Executes form and ensures that at least the given number of milliseconds
  have elapsed before returning result. Can be useful for protection against
  timing attacks, etc:
    (with-min-runtime 2000 <variable-time-form>)"
  [msecs form] `(with-min-runtime* ~(enc/as-pos-int msecs) (fn [] ~form)))

(comment (with-min-runtime 2000 (do (println "running") (Thread/sleep 1000) :done)))

;;;; Public data

(defn public-data
  "Given an encrypted Tempel byte[], returns a map of *UNVERIFIED* public
  (unencrypted) data embedded in the byte[].

  Possible keys:
    `:ba-aad`          - See `help:aad`
    `:keychain`        - Public-key part of encrypted `KeyChain`
    `:key-id`          - See `:embed-key-ids?` option of `encrypt-X` API
    `:receiver-key-id` - ''
    `:sender-key-id`   - ''
    `:has-hmac?`       - Does data have embedded HMAC?
    `:has-backup-key?` - Can data be decrypted with a secondary (backup) key?
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

  (when-not (enc/bytes?  ba-tempel-output)
    (enc/unexpected-arg! ba-tempel-output
      {:param           'ba-tempel-output
       :expected        'byte-array}))
  
  (bytes/with-in [in] ba-tempel-output
    (let [_                 (df/read-head! in)
          env-kid           (df/read-kid   in :envelope)
          flags             (df/read-flags in {:thaw/skip-unknown? true})
          ;; [kind version] (re-find #"^(\w+)-v(\d+)$" (name env-kid))
          flag?             #(contains? flags %)
          has-hmac?         (flag? :has-hmac)
          has-backup-key?   (flag? :has-backup-key)]

      (case env-kid
        :encrypted-with-password-v1
        (let [?ba-aad (bytes/read-dynamic-?ba in)]
          (enc/assoc-when
            {:kind :encrypted-with-password, :version 1}
            :ba-aad          ?ba-aad
            :has-hmac?       has-hmac?
            :has-backup-key? has-backup-key?))

        :encrypted-with-symmetric-key-v1
        (let [?ba-aad (bytes/read-dynamic-?ba  in)
              ?key-id (bytes/read-dynamic-?str in)]
          (enc/assoc-when
            {:kind :encrypted-with-symmetric-key, :version 1}
            :ba-aad          ?ba-aad
            :key-id          ?key-id
            :has-hmac?       has-hmac?
            :has-backup-key? has-backup-key?))

        (:encrypted-with-1-keypair-simple-v1
         :encrypted-with-1-keypair-hybrid-v1)
        (let [hybrid?   (= env-kid :encrypted-with-1-keypair-hybrid-v1)
              ?ba-aad   (when hybrid? (bytes/read-dynamic-?ba  in))
              key-algo                (df/read-kid             in :key-algo)
              ?key-id                 (bytes/read-dynamic-?str in)]
          (impl/key-algo! key-algo [:asym-cipher-algo])
          (enc/assoc-when
            {:kind :encrypted-with-1-keypair, :version 1, :key-algo key-algo}
            :scheme          (if hybrid? :hybrid :simple)
            :ba-aad          ?ba-aad
            :key-id          ?key-id
            :has-hmac?       has-hmac?
            :has-backup-key? has-backup-key?))

        :encrypted-with-2-keypairs-v1
        (let [?ba-aad      (bytes/read-dynamic-?ba  in)
              key-algo     (df/read-kid             in :key-algo)
              ?recp-key-id (bytes/read-dynamic-?str in)
              ?send-key-id (bytes/read-dynamic-?str in)]
          (impl/key-algo! key-algo [:ka-algo])
          (enc/assoc-when
            {:kind :encrypted-with-2-keypairs, :version 1, :key-algo key-algo}
            :ba-aad          ?ba-aad
            :receiver-key-id ?recp-key-id
            :sender-key-id   ?send-key-id
            :has-hmac?       has-hmac?
            :has-backup-key? has-backup-key?))

        :signed-v1
        (let [?ba-aad     (bytes/read-dynamic-?ba  in)
              key-algo    (df/read-kid             in :key-algo)
              ?key-id     (bytes/read-dynamic-?str in)
              ?ba-content (bytes/read-dynamic-?ba  in)]
          (impl/key-algo! key-algo [:sig-algo])
          (enc/assoc-when
            {:kind :signed, :version 1, :key-algo key-algo}
            :ba-aad     ?ba-aad
            :key-id     ?key-id
            :ba-content ?ba-content))

        :encrypted-keychain-v1
        (let [?ba-aad   (bytes/read-dynamic-?ba  in)
              ba-kc-pub (bytes/read-dynamic-ba   in)
              ?key-id   (bytes/read-dynamic-?str in)]
          (enc/assoc-when
            {:kind :encrypted-keychain, :version 1,
             :keychain (keys/keychain-restore nil ba-kc-pub)}
            :ba-aad          ?ba-aad
            :key-id          ?key-id
            :has-hmac?       has-hmac?
            :has-backup-key? has-backup-key?))

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
    :map
    (enc/assoc-some {}
      :ba-content ?ba-cnt
      :ba-aad     ?ba-aad)

    :_test ; Undocumented, used for tests
    (enc/assoc-some {}
      :aad (bytes/?utf8-ba->?str ?ba-aad)
      :cnt (bytes/?utf8-ba->?str ?ba-cnt))

    (enc/unexpected-arg! return-kind
      {:expected #{:ba-content :ba-aad :map}
       :context  context})))

(defn encrypt-with-password
  "Uses a symmetric cipher to encrypt the given byte[] content and return
  a byte[] that includes:
    - The encrypted content
    - Optional unencrypted AAD (see `help:aad`)
    - Envelope data necessary for decryption (specifies algorithms, etc.)

  Takes a password (string, byte[], or char[]).
  Password will be \"stretched\" using an appropriate \"Password-Based Key
  Derivation Function\" (PBKDF).

  Decrypt output with: `decrypt-with-password`.

  Options:
    `:ba-aad` - See `help:aad`
    `:ba-akm` - See `help:akm`

    And see `*config*` for details:
      `hash-algo`, `sym-cipher-algo`, `pbkdf-algo`, `pbkdf-nwf`,
      `embed-key-ids?`, `embed-hmac?`, `backup-key`, `backup-opts`."

  #_(df/reference-data-formats :encrypted-with-password-v1)
  {:arglists
   '([ba-content password &
      [{:keys
        [ba-aad ba-akm
         hash-algo sym-cipher-algo
         pbkdf-algo pbkdf-nwf
         embed-key-ids? embed-hmac?
         backup-key backup-opts]}]])}

  ^bytes
  [ba-content password & [opts]]
  (let [{:as opts+
         :keys
         [ba-aad ba-akm
          hash-algo sym-cipher-algo pbkdf-algo pbkdf-nwf
          embed-key-ids? embed-hmac?
          #_backup-key #_backup-opts]}
        (get-opts+ opts)

        _          (have? some? hash-algo sym-cipher-algo pbkdf-algo pbkdf-nwf)
        sck        (impl/as-symmetric-cipher-kit sym-cipher-algo)
        key-len    (impl/sck-key-len sck)

        ba-iv      (impl/rand-ba (max (impl/sck-iv-len sck) impl/min-iv-len))
        ba-salt    (impl/derive-ba-salt hash-algo ba-iv)

        pbkdf-nwf  (pbkdf/pbkdf-nwf-parse pbkdf-algo pbkdf-nwf)
        ba-key1    (let [ba-key0 (pbkdf/pbkdf pbkdf-algo key-len ba-salt password pbkdf-nwf)]
                     (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm))

        ba-ecnt    (let [ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                     (impl/sck-encrypt sck ba-iv ba-key2 ba-content ba-aad))

        ?ba-ekey1b (keys/get-backup-key-for-encryption ba-key1 opts+)
        ehmac-size (if embed-hmac? (impl/hmac-len hash-algo) 0)]

    (bytes/with-out [out baos]
      [64 ba-ecnt ba-aad ?ba-ekey1b ba-iv ehmac-size]
      (df/write-head          out)
      (df/write-kid           out :envelope :encrypted-with-password-v1)
      (df/write-flags         out nil {:has-hmac       (boolean embed-hmac?)
                                       :has-backup-key (boolean ?ba-ekey1b)})
      (bytes/write-dynamic-ba out ba-aad)
      (df/write-kid           out :hash-algo       hash-algo)
      (df/write-kid           out :sym-cipher-algo sym-cipher-algo)
      (df/write-kid           out :pbkdf-algo pbkdf-algo)
      (bytes/write-ushort     out             pbkdf-nwf)
      (bytes/write-dynamic-ba out nil #_ba-salt)
      (bytes/write-dynamic-ba out ba-iv)
      (bytes/write-dynamic-ba out ba-ecnt)
      (bytes/write-dynamic-ba out ?ba-ekey1b)
      (df/write-resv          out)
      (impl/write-ehmac       out baos embed-hmac? hash-algo ba-key1 ba-iv)
      (df/write-resv          out))))

(comment (public-data-test (encrypt-with-password (as-ba "cnt") "pwd")))

(defn decrypt-with-password
  "Complement of `encrypt-with-password`.

  Uses a symmetric cipher to decrypt the given byte[].
  Return value depends on `:return` option:
    `:ba-content` - Returns decrypted byte[] content (default)
    `:ba-aad`     - Returns verified unencrypted embedded ?byte[] AAD
    `:map`        - Returns {:keys [ba-aad ba-content]} map

  Takes a password (string, byte[], or char[]). Password will be \"stretched\"
  using an appropriate \"Password-Based Key Derivation Function\" (PBKDF).

  Will throw on decryption failure (bad password, etc.)."

  #_(df/reference-data-formats :encrypted-with-password-v1)
  {:arglists
   '([ba-encrypted password &
      [{:keys [return ba-akm backup-key backup-opts ignore-hmac?]
        :or   {return :ba-content}}]])}

  [ba-encrypted password & [opts]]
  (let [{:keys [return] :or {return :ba-content}} opts
        {:keys [ba-akm backup-key backup-opts ignore-hmac?] :as opts+}
        (get-opts+ opts)]

    (bytes/with-in [in bais] ba-encrypted
      (let [env-kid         :encrypted-with-password-v1
            _               (df/read-head!          in)
            _               (df/read-kid            in :envelope env-kid)
            _               (df/skip-flags          in)
            ?ba-aad         (bytes/read-dynamic-?ba in)
            hash-algo       (df/read-kid            in :hash-algo)
            sym-cipher-algo (df/read-kid            in :sym-cipher-algo)
            pbkdf-algo      (df/read-kid            in :pbkdf-algo)
            pbkdf-nwf       (bytes/read-ushort      in)
            ?ba-salt        (bytes/read-dynamic-?ba in)
            ba-iv           (bytes/read-dynamic-ba  in)
            ba-ecnt         (bytes/read-dynamic-ba  in)
            ?ba-ekey1b      (bytes/read-dynamic-?ba in)
            _               (df/read-resv!          in)
            ehmac*          (impl/read-ehmac*       in bais ba-encrypted)
            _               (df/read-resv!          in)

            hmac-pass!
            (fn [ba-key1]
              (if (or ignore-hmac? (impl/ehmac-pass? ehmac* ba-encrypted hash-algo ba-key1 ba-iv))
                ba-key1
                (throw (ex-info impl/error-msg-bad-ehmac {}))))

            sck      (impl/as-symmetric-cipher-kit sym-cipher-algo)
            ba-key1b (keys/get-backup-key-for-decryption ?ba-ekey1b opts+)
            ba-key1
            (or
              ba-key1b
              (let [key-len (impl/sck-key-len sck)
                    ba-salt (or ?ba-salt (impl/derive-ba-salt hash-algo ba-iv))
                    ba-key0 (pbkdf/pbkdf pbkdf-algo key-len ba-salt password pbkdf-nwf)]
                (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm)))

            ba-cnt
            (try
              (let [ba-key1 (hmac-pass!  ba-key1)
                    ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                (impl/sck-decrypt sck ba-iv ba-key2 ba-ecnt ?ba-aad))

              (catch Throwable t
                (if ba-key1b
                  (throw (ex-info impl/error-msg-bad-backup-key {} t))
                  (throw (ex-info impl/error-msg-bad-pwd        {} t)))))]

        (return-val env-kid return ba-cnt ?ba-aad)))))

(comment
  (let [ba-enc (encrypt-with-password (as-ba "cnt") "pwd")]
    (decrypt-with-password ba-enc "pwd" {:return :_test})))

(defn encrypt-with-symmetric-key
  "Uses a symmetric cipher to encrypt the given byte[] content and return
  a byte[] that includes:
    - The encrypted content
    - Optional unencrypted AAD (see `help:aad`)
    - Envelope data necessary for decryption (specifies algorithms, etc.)

  Takes a `KeyChain` (see `keychain`) or byte[] key.
  Decrypt output with: `decrypt-with-symmetric-key`.

  Options:
    `:ba-aad` - See `help:aad`
    `:ba-akm` - See `help:akm`

    And see `*config*` for details:
      `hash-algo`, `sym-cipher-algo`, `embed-key-ids?`,
      `backup-key`, `backup-opts`."

  #_(df/reference-data-formats :encrypted-with-symmetric-key-v1)
  {:arglists
   '([ba-content key-sym &
      [{:keys
        [ba-aad ba-akm
         hash-algo sym-cipher-algo
         embed-key-ids? embed-hmac?
         backup-key backup-opts]}]])}

  ^bytes
  [ba-content key-sym & [opts]]
  (let [{:as opts+
         :keys
         [ba-aad ba-akm
          hash-algo sym-cipher-algo
          embed-key-ids? embed-hmac?
          #_backup-key #_backup-opts]}
        (get-opts+ opts)

        _          (have? some? hash-algo sym-cipher-algo)
        ckey-sym   (keys/get-ckeys-sym-cipher key-sym)
        {:keys [key-sym key-id]} @ckey-sym
        ba-key0    (have enc/bytes? key-sym)
        ?ba-key-id (when embed-key-ids? (bytes/?str->?utf8-ba key-id))

        sck        (impl/as-symmetric-cipher-kit sym-cipher-algo)
        ba-iv      (impl/rand-ba (max (impl/sck-iv-len sck) impl/min-iv-len))
        ba-key1    (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm)

        ba-ecnt    (let [ba-key1 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                     (impl/sck-encrypt sck ba-iv ba-key1 ba-content ba-aad))

        ?ba-ekey1b (keys/get-backup-key-for-encryption ba-key1 opts+)
        ehmac-size (if embed-hmac? (impl/hmac-len hash-algo) 0)]

    (bytes/with-out [out baos]
      [32 ba-ecnt ba-aad ?ba-key-id ?ba-ekey1b ba-iv ehmac-size]
      (df/write-head          out)
      (df/write-kid           out :envelope :encrypted-with-symmetric-key-v1)
      (df/write-flags         out nil {:has-hmac       (boolean embed-hmac?)
                                       :has-backup-key (boolean ?ba-ekey1b)})
      (bytes/write-dynamic-ba out ba-aad)
      (bytes/write-dynamic-ba out ?ba-key-id)
      (df/write-kid           out :hash-algo       hash-algo)
      (df/write-kid           out :sym-cipher-algo sym-cipher-algo)
      (bytes/write-dynamic-ba out ba-iv)
      (bytes/write-dynamic-ba out ba-ecnt)
      (bytes/write-dynamic-ba out ?ba-ekey1b)
      (df/write-resv          out)
      (impl/write-ehmac       out baos embed-hmac? hash-algo ba-key1 ba-iv)
      (df/write-resv          out))))

(comment (public-data-test (encrypt-with-symmetric-key (as-ba "cnt") (keychain))))

(defn decrypt-with-symmetric-key
  "Complement of `encrypt-with-symmetric-key`.

  Uses a symmetric cipher to decrypt the given byte[].
  Return value depends on `:return` option:
    `:ba-content` - Returns decrypted byte[] content (default)
    `:ba-aad`     - Returns verified unencrypted embedded ?byte[] AAD
    `:map`        - Returns {:keys [ba-aad ba-content]} map

  Takes a `KeyChain` (see `keychain`) or byte[] key.
  Will throw on decryption failure (bad key, etc.)."

  #_(df/reference-data-formats :encrypted-with-symmetric-key-v1)
  {:arglists
   '([ba-encrypted key-sym &
      [{:keys [return ba-akm backup-key backup-opts ignore-hmac?]
        :or   {return :ba-content}}]])}

  [ba-encrypted key-sym & [opts]]
  (let [{:keys [return] :or {return :ba-content}} opts
        {:keys [ba-akm backup-key backup-opts ignore-hmac?] :as opts+}
        (get-opts+ opts)]

    (bytes/with-in [in bais] ba-encrypted
      (let [env-kid         :encrypted-with-symmetric-key-v1
            _               (df/read-head!           in)
            _               (df/read-kid             in :envelope env-kid)
            _               (df/skip-flags           in)
            ?ba-aad         (bytes/read-dynamic-?ba  in)
            ?key-id         (bytes/read-dynamic-?str in)
            hash-algo       (df/read-kid             in :hash-algo)
            sym-cipher-algo (df/read-kid             in :sym-cipher-algo)
            ba-iv           (bytes/read-dynamic-ba   in)
            ba-ecnt         (bytes/read-dynamic-ba   in)
            ?ba-ekey1b      (bytes/read-dynamic-?ba  in)
            _               (df/read-resv!           in)
            ehmac*          (impl/read-ehmac*        in bais ba-encrypted)
            _               (df/read-resv!           in)

            hmac-pass!
            (fn [ba-key1]
              (if (or ignore-hmac? (impl/ehmac-pass? ehmac* ba-encrypted hash-algo ba-key1 ba-iv))
                ba-key1
                (throw (ex-info impl/error-msg-bad-ehmac {}))))

            sck (impl/as-symmetric-cipher-kit sym-cipher-algo)
            ba-cnt
            (if-let [ba-key1 (keys/get-backup-key-for-decryption ?ba-ekey1b opts+)]
              (try
                (let [ba-key1 (hmac-pass! ba-key1)
                      ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                  (impl/sck-decrypt sck ba-iv ba-key2 ba-ecnt ?ba-aad))

                (catch Throwable t
                  (throw (ex-info impl/error-msg-bad-backup-key {} t))))

              (let [ckeys-sym (keys/get-ckeys-sym-cipher key-sym ?key-id)]
                (keys/try-decrypt-with-keys! `decrypt-with-symmetric-key
                  (some? ?key-id) ckeys-sym
                  (fn [ckey-sym]
                    (let [{:keys [key-sym]} @ckey-sym
                          ba-key0 (have enc/bytes? key-sym)
                          ba-key1 (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm)
                          ba-key1 (hmac-pass!  ba-key1)
                          ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)
                          ba-cnt  (impl/sck-decrypt sck ba-iv ba-key2 ba-ecnt ?ba-aad)]
                      ba-cnt)))))]

        (return-val env-kid return ba-cnt ?ba-aad)))))

(comment
  (let [kc     (keychain)
        ba-enc (encrypt-with-symmetric-key (as-ba "cnt") kc)]
    (decrypt-with-symmetric-key ba-enc kc {:return :_test})))

(defn encrypt-with-1-keypair
  "Uses a symmetric or hybrid (symmetric + asymmetric) scheme to encrypt the
  given content byte[] and return a byte[] that includes:
    - The encrypted content
    - Optional unencrypted AAD (see `help:aad`)
    - Envelope data necessary for decryption (specifies algorithms, etc.)

  Takes a `KeyChain` (see `keychain`) or `KeyPair` (see `keypair-create`).
  Key algorithm must support use as an asymmetric cipher.
  Suitable algorithms: `:rsa-<nbits>`.

  Encryption uses receiver's asymmetric public  key.
  Decryption uses receiver's asymmetric private key.

  Decrypt output byte[] with: `decrypt-with-1-keypair`.

  Options:
    `:ba-aad` - See `help:aad`
    `:ba-akm` - See `help:akm`

    And see `*config*` for details:
      `hash-algo`, `sym-cipher-algo`, `asym-cipher-algo`,
      `embed-key-ids`, `backup-key`, `backup-opts`."

  #_(df/reference-data-formats :encrypted-with-1-keypair-<type>-v1)
  {:arglists
   '([ba-content receiver-key-pub &
      [{:keys
        [ba-aad ba-akm
         hash-algo sym-cipher-algo asym-cipher-algo
         embed-key-ids? embed-hmac?
         backup-key backup-opts]}]])}

  ^bytes
  [ba-content receiver-key-pub & [opts]]
  (let [{:keys [scheme] :or {scheme :hybrid}} opts ; Undocumented
        {:as opts+
         :keys
         [ba-aad ba-akm
          #_hash-algo #_sym-cipher-algo asym-cipher-algo
          embed-key-ids? embed-hmac?
          backup-key #_backup-opts]}
        (get-opts+ opts)

        ckey-pub (keys/get-ckeys-asym-cipher receiver-key-pub)
        {:keys [key-pub key-id key-algo]} @ckey-pub

        ?ba-key-id       (when embed-key-ids? (bytes/?str->?utf8-ba key-id))
        asym-cipher-algo (have (or asym-cipher-algo (get (impl/key-algo-info key-algo) :asym-cipher-algo)))

        simple-scheme? ; Optimization when encrypting symmetric keys, etc.
        (let [large-cnt?   (> (alength ^bytes ba-content) 62) ; RSA limitation
              need-hybrid? (or embed-hmac? ba-aad ba-akm backup-key large-cnt?)]

          (case scheme
            :auto   (if need-hybrid? false true) ; Used internally for ekey1bs
            :hybrid                  false ; Default
            :simple
            (if need-hybrid?
              (throw
                (ex-info "Cannot use `:simple` scheme (>0 opts require `:hybrid`)"
                  (enc/assoc-when {}
                    :large-content?          large-cnt?
                    :embed-hmac?    (boolean embed-hmac?)
                    :ba-aad?        (boolean ba-aad)
                    :ba-akm?        (boolean ba-akm)
                    :backup-key?    (boolean backup-key))))
              true)))]

    (if simple-scheme?
      #_(df/reference-data-formats :encrypted-with-1-keypair-simple-v1)
      (let [ba-ecnt (impl/encrypt-asymmetric asym-cipher-algo key-algo key-pub ba-content)]
        (bytes/with-out [out] [32 ba-ecnt]
          (df/write-head             out)
          (df/write-kid              out :envelope :encrypted-with-1-keypair-simple-v1)
          (df/write-flags            out nil nil)
          ;; (bytes/write-dynamic-ba out ba-aad
          (df/write-kid              out :key-algo key-algo)
          (bytes/write-dynamic-ba    out ?ba-key-id)
          ;; (df/write-kid           out :hash-algo        hash-algo)
          ;; (df/write-kid           out :sym-cipher-algo  sym-cipher-algo)
          (df/write-kid              out :asym-cipher-algo asym-cipher-algo)
          ;; (bytes/write-dynamic-ba out ba-iv)
          (bytes/write-dynamic-ba    out ba-ecnt)
          ;; (bytes/write-dynamic-ba out ba-ekey0)
          #_(bytes/write-dynamic-ba  out ?ba-ekey1b)
          (df/write-resv             out)
          #_(impl/write-ehmac        out baos false nil nil nil)
          #_(df/write-resv           out)))

      ;; Hybrid scheme:
      ;;   - Use a random 1-time symmetric key to encrypt content
      ;;   - Wrap symmetric key with asymmetric encryption, embed
      #_(df/reference-data-formats :encrypted-with-1-keypair-hybrid-v1)
      (let [{:keys [hash-algo sym-cipher-algo]} opts+
            _ (have? some? hash-algo sym-cipher-algo)

            sck        (impl/as-symmetric-cipher-kit sym-cipher-algo)
            ba-iv      (impl/rand-ba (max (impl/sck-iv-len  sck) impl/min-iv-len))
            ba-key0    (impl/rand-ba      (impl/sck-key-len sck)) ; Random 1-time symmetric key
            ba-key1    (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm)

            ba-ecnt    (let [ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                         (impl/sck-encrypt sck ba-iv ba-key2 ba-content ba-aad))

            ba-ekey0   (impl/encrypt-asymmetric asym-cipher-algo key-algo key-pub ba-key0)
            ?ba-ekey1b (keys/get-backup-key-for-encryption ba-key1 opts+)
            ehmac-size (if embed-hmac? (impl/hmac-len hash-algo) 0)]

        (bytes/with-out [out baos]
          [64 ba-ecnt ba-aad ?ba-ekey1b ba-iv ba-ekey0 ehmac-size]
          (df/write-head          out)
          (df/write-kid           out :envelope :encrypted-with-1-keypair-hybrid-v1)
          (df/write-flags         out nil {:has-hmac       (boolean embed-hmac?)
                                           :has-backup-key (boolean ?ba-ekey1b)})
          (bytes/write-dynamic-ba out ba-aad)
          (df/write-kid           out :key-algo key-algo)
          (bytes/write-dynamic-ba out ?ba-key-id)
          (df/write-kid           out :hash-algo        hash-algo)
          (df/write-kid           out :sym-cipher-algo  sym-cipher-algo)
          (df/write-kid           out :asym-cipher-algo asym-cipher-algo)
          (bytes/write-dynamic-ba out ba-iv)
          (bytes/write-dynamic-ba out ba-ecnt)
          (bytes/write-dynamic-ba out ba-ekey0)
          (bytes/write-dynamic-ba out ?ba-ekey1b)
          (df/write-resv          out)
          (impl/write-ehmac       out baos embed-hmac? hash-algo ba-key1 ba-iv)
          (df/write-resv          out))))))

(comment
  [(public-data-test (encrypt-with-1-keypair (impl/rand-ba 32)  (keychain) {:scheme :auto :embed-hmac? false}))
   (public-data-test (encrypt-with-1-keypair (impl/rand-ba 128) (keychain) {:scheme :auto :embed-hmac? false}))])

(defn decrypt-with-1-keypair
  "Complement of `encrypt-with-1-keypair`.

  Uses a hybrid (symmetric + asymmetric) scheme to decrypt the given byte[].
  Return value depends on `:return` option:
    `:ba-content` - Returns decrypted byte[] content (default)
    `:ba-aad`     - Returns verified unencrypted embedded ?byte[] AAD
    `:map`        - Returns {:keys [ba-aad ba-content]} map

  Takes a `KeyChain` (see `keychain`) or `KeyPair` (see `keypair-create`).
  Key algorithm must support use as an asymmetric cipher.
  Suitable algorithms: `:rsa-<nbits>`.

  Encryption uses receiver's asymmetric public  key.
  Decryption uses receiver's asymmetric private key.

  Will throw on decryption failure (bad key, etc.)."

  #_(df/reference-data-formats :encrypted-with-1-keypair-<type>-v1)
  {:arglists
   '([ba-encrypted receiver-key-prv &
      [:keys [return ba-akm backup-key backup-opts ignore-hmac?]
       :or   {return :ba-content}]])}

  [ba-encrypted receiver-key-prv & [opts]]
  (let [{:keys [return] :or {return :ba-content}} opts
        {:keys [ba-akm backup-key backup-opts ignore-hmac?] :as opts+}
        (get-opts+ opts)]

    (bytes/with-in [in bais] ba-encrypted
      (let [_       (df/read-head! in)
            env-kid (df/read-kid   in :envelope
                      #{:encrypted-with-1-keypair-hybrid-v1
                        :encrypted-with-1-keypair-simple-v1})
            _       (df/skip-flags in)]

        (case env-kid

          :encrypted-with-1-keypair-simple-v1
          #_(df/reference-data-formats :encrypted-with-1-keypair-simple-v1)
          (let [_
                (when ba-akm
                  (throw (ex-info "Failed to decrypt Tempel data (no AKM support)" {})))

                ;; ?ba-aad         (bytes/read-dynamic-?ba  in)
                key-algo           (df/read-kid             in :key-algo)
                ?key-id            (bytes/read-dynamic-?str in)
                ;; hash-algo       (df/read-kid             in :hash-algo)
                ;; sym-cipher-algo (df/read-kid             in :sym-cipher-algo)
                asym-cipher-algo   (df/read-kid             in :asym-cipher-algo)
                ;; ba-iv           (bytes/read-dynamic-ba   in)
                ba-ecnt            (bytes/read-dynamic-ba   in)
                ;; ba-ekey0        (bytes/read-dynamic-ba   in)
                ;; ?ba-ekey1b      (bytes/read-dynamic-?ba  in)
                _                  (df/read-resv!           in)
                ;; ehmac*          (impl/read-ehmac*        in bais ba-encrypted)
                ;;_                (df/read-resv!           in)

                ckeys-prv (keys/get-ckeys-asym-cipher receiver-key-prv key-algo ?key-id)
                ba-cnt
                (keys/try-decrypt-with-keys! `decrypt-with-1-keypair
                  (some? ?key-id) ckeys-prv
                  (fn [ckey-prv]
                    (let [{:keys [key-prv]} @ckey-prv
                          ba-cnt (impl/decrypt-asymmetric asym-cipher-algo key-algo key-prv ba-ecnt)]
                      ba-cnt)))]

            (return-val env-kid return ba-cnt nil))

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
                ba-ekey0         (bytes/read-dynamic-ba   in)
                ?ba-ekey1b       (bytes/read-dynamic-?ba  in)
                _                (df/read-resv!           in)
                ehmac*           (impl/read-ehmac*        in bais ba-encrypted)
                _                (df/read-resv!           in)

                hmac-pass!
                (fn [ba-key1]
                  (if (or ignore-hmac? (impl/ehmac-pass? ehmac* ba-encrypted hash-algo ba-key1 ba-iv))
                    ba-key1
                    (throw (ex-info impl/error-msg-bad-ehmac {}))))

                sck (impl/as-symmetric-cipher-kit sym-cipher-algo)
                ba-cnt
                (if-let [ba-key1 (keys/get-backup-key-for-decryption ?ba-ekey1b opts+)]
                  (try
                    (let [ba-key1 (hmac-pass!  ba-key1)
                          ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                      (impl/sck-decrypt sck ba-iv ba-key2 ba-ecnt ?ba-aad))

                    (catch Throwable t
                      (throw (ex-info impl/error-msg-bad-backup-key {} t))))

                  (let [ckeys-prv (keys/get-ckeys-asym-cipher receiver-key-prv key-algo ?key-id)]
                    (keys/try-decrypt-with-keys! `decrypt-with-1-keypair
                      (some? ?key-id) ckeys-prv
                      (fn [ckey-prv]
                        (let [{:keys [key-prv]} @ckey-prv
                              ba-key0 (impl/decrypt-asymmetric asym-cipher-algo key-algo key-prv ba-ekey0)
                              ba-key1 (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm)
                              ba-key1 (hmac-pass!  ba-key1)
                              ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)
                              ba-cnt  (impl/sck-decrypt sck ba-iv ba-key2 ba-ecnt ?ba-aad)]
                          ba-cnt)))))]

            (return-val env-kid return ba-cnt ?ba-aad))

          (enc/unexpected-arg! env-kid
            {:context `decrypt-with-1-keypair
             :expected
             #{:encrypted-with-1-keypair-hybrid-v1
               :encrypted-with-1-keypair-simple-v1}}))))))

(comment
  (let [kc     (keychain)
        ba-enc (encrypt-with-1-keypair (as-ba "cnt") kc)]
    (decrypt-with-1-keypair ba-enc kc {:return :_test})))

(defn encrypt-with-2-keypairs
  "Uses a hybrid (symmetric + asymmetric) scheme to encrypt the given content
  byte[] and return a byte[] that includes:
    - The encrypted content
    - Optional unencrypted AAD (see `help:aad`)
    - Envelope data necessary for decryption (specifies algorithms, etc.)

  Takes `KeyChain`s (see `keychain`) and/or `KeyPair`s (see `keypair-create`).
  Key algorithm must support key agreement.
  Suitable algorithms: `:dh-<nbits>`, `:ec-<curve>`.

  Encryption uses:
    - Receiver's asymmetric public  key
    - Sender's   asymmetric private key

  Decryption uses:
    - Receiver's asymmetric private key
    - Sender's   asymmetric public  key

  Decrypt output byte[] with: `decrypt-with-2-keypairs`.

  Options:
    `:ba-aad` - See `help:aad`
    `:ba-akm` - See `help:akm`

    And see `*config*` for details:
      `hash-algo`, `ka-algo`, `sym-cipher-algo`,
      `embed-key-ids?`, `backup-key`, `backup-opts`."

  #_(df/reference-data-formats :encrypted-with-2-keypairs-v1)
  {:arglists
   '([ba-content receiver-key-pub sender-key-prv &
      [{:keys
        [ba-aad ba-akm
         hash-algo ka-algo sym-cipher-algo
         embed-key-ids? embed-hmac?
         backup-key backup-opts]}]])}

  ^bytes
  [ba-content receiver-key-pub sender-key-prv & [opts]]
  ;; Hybrid scheme:
  ;;   - Gen symmetric key via key agreement
  ;;   - Use symmetric key to encrypt content
  (let [{:as opts+
         :keys
         [ba-aad ba-akm
          hash-algo ka-algo sym-cipher-algo
          embed-key-ids? embed-hmac?
          #_backup-key #_backup-opts]}
        (get-opts+ opts)

        _ (have? some? hash-algo sym-cipher-algo)

        [recvr-ckey-pub sendr-ckey-prv] (keys/get-ckeys-ka receiver-key-pub sender-key-prv)
        {:keys [key-pub         ], recvr-key-id :key-id} @recvr-ckey-pub
        {:keys [key-prv key-algo], sendr-key-id :key-id} @sendr-ckey-prv

        ?ba-recvr-key-id (when embed-key-ids? (bytes/?str->?utf8-ba recvr-key-id))
        ?ba-sendr-key-id (when embed-key-ids? (bytes/?str->?utf8-ba sendr-key-id))

        ka-algo (have (or ka-algo (get (impl/key-algo-info key-algo) :ka-algo)))
        sck     (impl/as-symmetric-cipher-kit sym-cipher-algo)
        ba-iv   (impl/rand-ba (max (impl/sck-iv-len sck) impl/min-iv-len))
        ba-key1
        (let [ba-key0 (impl/key-shared-create ka-algo key-algo key-prv key-pub)]
          (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm))

        ba-ecnt    (let [ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                     (impl/sck-encrypt sck ba-iv ba-key2 ba-content ba-aad))

        ?ba-ekey1b (keys/get-backup-key-for-encryption ba-key1 opts+)
        ehmac-size (if embed-hmac? (impl/hmac-len hash-algo) 0)]

    (bytes/with-out [out baos]
      [32 ba-ecnt ba-aad ?ba-recvr-key-id ?ba-sendr-key-id ?ba-ekey1b ba-iv ehmac-size]
      (df/write-head          out)
      (df/write-kid           out :envelope :encrypted-with-2-keypairs-v1)
      (df/write-flags         out nil {:has-hmac       (boolean embed-hmac?)
                                       :has-backup-key (boolean ?ba-ekey1b)})
      (bytes/write-dynamic-ba out ba-aad)
      (df/write-kid           out :key-algo key-algo)
      (bytes/write-dynamic-ba out ?ba-recvr-key-id)
      (bytes/write-dynamic-ba out ?ba-sendr-key-id)
      (df/write-kid           out :hash-algo       hash-algo)
      (df/write-kid           out :ka-algo         ka-algo)
      (df/write-kid           out :sym-cipher-algo sym-cipher-algo)
      (bytes/write-dynamic-ba out ba-iv)
      (bytes/write-dynamic-ba out ba-ecnt)
      (bytes/write-dynamic-ba out ?ba-ekey1b)
      (df/write-resv          out)
      (impl/write-ehmac       out baos embed-hmac? hash-algo ba-key1 ba-iv)
      (df/write-resv          out))))

(comment (public-data-test (encrypt-with-2-keypairs (as-ba "cnt") (keychain) (keychain))))

(defn decrypt-with-2-keypairs
  "Complement of `encrypt-with-2-keypairs`.

  Uses a hybrid (symmetric + asymmetric) scheme to decrypt the given byte[].
  Return value depends on `:return` option:
    `:ba-content` - Returns decrypted byte[] content (default)
    `:ba-aad`     - Returns verified unencrypted embedded ?byte[] AAD
    `:map`        - Returns {:keys [ba-aad ba-content]} map

  Takes `KeyChain`s (see `keychain`) and/or `KeyPair`s (see `keypair-create`).
  Key algorithm must support key agreement.
  Suitable algorithms: `:dh-<nbits>`, `:ec-<curve>`.

  Encryption uses:
    - Receiver's asymmetric public  key
    - Sender's   asymmetric private key

  Decryption uses:
    - Receiver's asymmetric private key
    - Sender's   asymmetric public  key

  Will throw on decryption failure (bad key, etc.)."

  #_(df/reference-data-formats :encrypted-with-2-keypairs-v1)
  {:arglists
   '([ba-encrypted receiver-key-prv sender-key-pub &
      [{:keys [return ba-akm backup-key backup-opts ignore-hmac?]
        :or   {return :ba-content}}]])}

  [ba-encrypted receiver-key-prv sender-key-pub & [opts]]
  (let [{:keys [return] :or {return :ba-content}} opts
        {:keys [ba-akm backup-key backup-opts ignore-hmac?] :as opts+}
        (get-opts+ opts)]

    (bytes/with-in [in bais] ba-encrypted
      (let [env-kid         :encrypted-with-2-keypairs-v1
            _               (df/read-head!           in)
            _               (df/read-kid             in :envelope env-kid)
            _               (df/skip-flags           in)
            ?ba-aad         (bytes/read-dynamic-?ba  in)
            key-algo        (df/read-kid             in :key-algo)
            ?recvr-key-id   (bytes/read-dynamic-?str in)
            ?sendr-key-id   (bytes/read-dynamic-?str in)

            hash-algo       (df/read-kid             in :hash-algo)
            ka-algo         (df/read-kid             in :ka-algo)
            sym-cipher-algo (df/read-kid             in :sym-cipher-algo)
            ba-iv           (bytes/read-dynamic-ba   in)
            ba-ecnt         (bytes/read-dynamic-ba   in)
            ?ba-ekey1b      (bytes/read-dynamic-?ba  in)
            _               (df/read-resv!           in)
            ehmac*          (impl/read-ehmac*        in bais ba-encrypted)
            _               (df/read-resv!           in)

            hmac-pass!
            (fn [ba-key1]
              (if (or ignore-hmac? (impl/ehmac-pass? ehmac* ba-encrypted hash-algo ba-key1 ba-iv))
                ba-key1
                (throw (ex-info impl/error-msg-bad-ehmac {}))))

            sck (impl/as-symmetric-cipher-kit sym-cipher-algo)
            ba-cnt
            (if-let [ba-key1 (keys/get-backup-key-for-decryption ?ba-ekey1b opts+)]
              (try
                (let [ba-key1 (hmac-pass!  ba-key1)
                      ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                  (impl/sck-decrypt sck ba-iv ba-key2 ba-ecnt ?ba-aad))

                (catch Throwable t
                  (throw (ex-info impl/error-msg-bad-backup-key {} t))))

              (let [ckey-pairs ; [[<recvr-ckey-prv> <sendr-ckey-pub>] ...]
                    (keys/get-ckeys-ka key-algo
                      [receiver-key-prv ?recvr-key-id]
                      [sender-key-pub   ?sendr-key-id])]

                (keys/try-decrypt-with-keys! `decrypt-with-2-keypairs
                  (some? ?recvr-key-id) ckey-pairs
                  (fn [[recvr-ckey-prv sendr-ckey-pub]]
                    (let [{:keys [key-prv]} @recvr-ckey-prv
                          {:keys [key-pub]} @sendr-ckey-pub

                          ba-key0 (impl/key-shared-create ka-algo key-algo key-prv key-pub)
                          ba-key1 (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm)
                          ba-key1 (hmac-pass! ba-key1)
                          ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)
                          ba-cnt  (impl/sck-decrypt sck ba-iv ba-key2 ba-ecnt ?ba-aad)]

                      ba-cnt)))))]

        (return-val env-kid return ba-cnt ?ba-aad)))))

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
    - Optional unencrypted AAD     (see `help:aad`)
    - Envelope data necessary for verification (specifies algorithms, etc.)

  Produces:
    - Signed content when `embed-content?` is true (default)
    - A signature    when `embed-content?` is false

  Takes a `KeyChain` (see `keychain`) or `KeyPair` (see `keypair-create`).
  Key algorithm must support signatures.
  Suitable algorithms: `:rsa-<nbits>`, `:ec-<curve>`.

  Signing      uses signer's asymmetric private key.
  Verification uses signer's asymmetric public  key.

  Verify with: `signed`.

  Options:
    `:ba-aad`         - See `help:aad`
    `:ba-akm`         - See `help:akm`
    `:embed-content?` - See usage info above

    And see `*config*` for details:
      `hash-algo`, `sig-algo`, `embed-key-ids?`."

  #_(df/reference-data-formats :signed-v1)
  {:arglists
   '([ba-content signer-key-prv &
      [{:keys
        [ba-aad ba-akm embed-content?
         hash-algo sig-algo
         embed-key-ids? embed-content?]

        :or {embed-content? true}}]])}

  ^bytes
  [ba-content signer-key-prv & [opts]]
  (let [{:keys [embed-content?] :or {embed-content? true}} opts
        {:as opts+
         :keys
         [ba-aad ba-akm
          hash-algo sig-algo
          embed-key-ids?]}
        (get-opts+ opts)

        _ (have? some? hash-algo)

        ckey-prv (keys/get-ckeys-sig signer-key-prv)
        {:keys [key-prv key-id key-algo]} @ckey-prv
        ?ba-key-id (when embed-key-ids? (bytes/?str->?utf8-ba key-id))
        ?ba-em-cnt (when embed-content? ba-content)

        sig-algo   (have (or sig-algo (get (impl/key-algo-info key-algo) :sig-algo)))
        ba-to-sign (impl/hash-ba-cascade hash-algo ba-content ba-akm ba-aad)
        ba-sig     (impl/signature-create sig-algo key-algo key-prv ba-to-sign)]

    (bytes/with-out [out]
      [11 ba-aad ?ba-key-id ba-sig ?ba-em-cnt]
      (df/write-head          out)
      (df/write-kid           out :envelope :signed-v1)
      (df/write-flags         out nil nil)
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
    `:map`        - Returns {:keys [ba-aad ba-content]} map (default)

  Returns nil when verification fails.

  Takes a `KeyChain` (see `keychain`) or `KeyPair` (see `keypair-create`).
  Key algorithm must support signatures.
  Suitable algorithms: `:rsa-<nbits>`, `:ec-<curve>`.

  Signing      uses signer's asymmetric private key.
  Verification uses signer's asymmetric public  key."

  #_(df/reference-data-formats :signature-v1)
  {:arglists
   '([ba-signed signer-key-pub &
      [{:keys [ba-content return ba-akm]
        :or   {return :map}}]])}

  [ba-signed signer-key-pub & [opts]]
  (let [{:keys [ba-content return] :or {return :map}} opts
        {:keys [ba-akm] :as opts+}
        (get-opts+ opts)]

    (bytes/with-in [in] ba-signed
      (let [env-kid    :signed-v1
            _          (df/read-head!           in)
            _          (df/read-kid             in :envelope env-kid)
            _          (df/skip-flags           in)
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
          (return-val `signed return ba-content ba-aad))))))

(comment
  (let [kc        (keychain)
        ba-signed (sign (as-ba "cnt") kc {:ba-aad (as-ba "aad")})]
    (signed ba-signed kc {:return :map #_:_test})))
