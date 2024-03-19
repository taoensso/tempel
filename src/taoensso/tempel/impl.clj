(ns ^:no-doc taoensso.tempel.impl
  "Private ns, implementation detail.
  Low level cryptography stuff.

  Notes:
    - These low-level utils should use minimal/zero envelope data!
    - For JVM crypto algorithm names, Ref.
      <https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html>,
      <https://docs.oracle.com/en/java/javase/18/docs/specs/security/standard-names.html>, etc."

  (:refer-clojure :exclude [rand-nth])
  (:require
   [taoensso.encore       :as enc   :refer [have have?]]
   [taoensso.encore.bytes :as bytes :refer [as-ba]]))

(comment
  (remove-ns 'taoensso.tempel.impl)
  (:api (enc/interns-overview)))

;; TODO Consider :symmetric-<nbits> key-algo, etc.
;; Benefits not currently worth the user-side complexity so we instead
;; just default to max (256)

;;;; IDs
;;
;; ✓ pbkdf-kit        - #{:scrypt-r8p1-v1 :pbkdf2-hmac-sha-256-v1 :sha-512-v1-deprecated}
;; ✓ sym-cipher-kit   - #{:aes-gcm-<nbits>-v1 :aes-cbc-<nbits>-v1-deprecated :chacha20-poly1305-v1}
;;
;; ✓ hash-algo        - #{:md5 :sha-1 :sha-256 :sha-512}
;; ✓ sym-cipher-algo  - #{:aes-gcm :aes-cbc :chacha20-poly1305}
;; ✓ asym-cipher-algo - #{:rsa-oaep-sha-256-mgf1}
;; ✓ sig-algo         - #{:sha-<nbits>-rsa :sha-<nbits>-ecdsa}
;;
;; ✓ ka-algo          - #{:dh :ecdh}
;; ✓ kf-algo          - #{:rsa :dh :ec}
;; ✓ key-algo         - #{:rsa-<nbits> :dh-<nbits> :ec-<curve> :symmetric}
;; ✓ key-type         - #{:sym :pub :prv}
;; ✓ key-capability   - #{:ka :sig :sym-cipher :asym-cipher}

;;;; Misc

(defmacro non-throwing? [form] `(try (do ~form true) (catch Throwable _# false)))

(defn missing-dep! [dep maven-gid context]
  (throw
    (ex-info
      (str "Missing optional dependency: `" maven-gid "`")
      {:dependency     dep
       :maven-group-id maven-gid
       :context        context})))

(comment
  (missing-dep!
    'org.apache.commons.codec.binary.Hex
    'commons-codec/commons-codec
    'context))

(let [bytes?  enc/bytes?
      ba-hash enc/ba-hash
      ba=     enc/ba=]

  (defn cnt-hash
    ([x  ] (if (bytes? x) (ba-hash x) (hash x)))
    ([x y] (hash [(cnt-hash x) (cnt-hash y)])))

  (defn cnt= [x y]
    (or (identical? x y)
      (and (= (type x) (type y)) (if (bytes? x) (ba= x y) (= x y))))))

;;;; Randomness

(do
  (def ^:dynamic *srng*
    "(fn instance-fn []) => `java.security.SecureRandom`.
    Used as the sole source of randomness in Tempel.
    See also `srng`, `with-srng`, `with-srng-insecure-deterministic`."
    enc/secure-rng)

  (defn srng
    "Returns `java.security.SecureRandom` instance by calling (*srng*).
    See also `*srng*`."
    ^java.security.SecureRandom [] (*srng*))

  (defmacro ^:public with-srng
    "Evaluates body with given (instance-fn) used as sole source of
    randomness in Tempel.

    (instance-fn) should return a `java.security.SecureRandom` instance."
    [instance-fn & body] `(enc/binding [*srng* ~instance-fn] ~@body))

  (defmacro ^:public with-srng-insecure-deterministic!!!
    "Evaluates body with *INSECURE* deterministic `java.util.Random` used
    as sole source of randomness in Tempel.

    Never use when encrypting real data, etc. Provided only for testing."
    [long-seed & body]
    `(let [mock-srng# (enc/secure-rng-mock!!! ~long-seed)]
       (with-srng (fn [] mock-srng#) ~@body))))

(defn ^:public rand-ba
  "Returns secure random byte[] of given length:
    (rand-ba 32) => random 32 byte (256 bit) byte[]."
  ^bytes [len]
  (let [ba (byte-array (int len))]
    (.nextBytes (srng) ba)
    (do                ba)))

(do
  (defn rand-hex-str ^String [nbytes] (enc/ba->hex-str (rand-ba nbytes)))
  (defn rand-nth             [coll] (nth coll (int (* (.nextDouble   (srng)) (count coll)))))
  (defn rand-double  ^double []                       (.nextDouble   (srng)))
  (defn rand-gauss   ^double []                       (.nextGaussian (srng)))
  (defn rand-bool            []                       (.nextBoolean  (srng)))
  (defn rand-long
    (^long   [    ]                      (.nextLong   (srng)))
    (^long   [nmax] (long (* (long nmax) (.nextDouble (srng)))))))

(comment
  (enc/qb 1e6 (rand-long)) ; 616.31
  (with-srng enc/secure-rng              (rand-long))
  (with-srng-insecure-deterministic!!! 5 (rand-long)))

;;;; Hashing

;; (defn hash-murmur3 ^long [^String s] (clojure.lang.Murmur3/hashUnencodedChars s))
;; (comment (hash-murmur3 "hello"))

(let [md-md5_     (enc/thread-local (java.security.MessageDigest/getInstance "MD5"))
      md-sha-1_   (enc/thread-local (java.security.MessageDigest/getInstance "SHA-1"))
      md-sha-256_ (enc/thread-local (java.security.MessageDigest/getInstance "SHA-256"))
      md-sha-512_ (enc/thread-local (java.security.MessageDigest/getInstance "SHA-512"))]

  (defn as-message-digest
    "Returns `java.security.MessageDigest`, or throws.
    Takes `hash-algo` ∈ #{:md5 :sha-1 :sha-256 :sha-512}."
    ^java.security.MessageDigest [hash-algo]
    (case hash-algo
      :md5     @md-md5_
      :sha-1   @md-sha-1_
      :sha-256 @md-sha-256_
      :sha-512 @md-sha-512_
      (enc/unexpected-arg! hash-algo
        {:expected #{:md5 :sha-1 :sha-256 :sha-512}
         :context  `as-message-digest}))))

(let [ba0 (byte-array 0)]
  (defn hash-ba-concat
    "Returns hash digest of given byte[] ?content.
    Takes `hash-algo` ∈ #{:md5 :sha-1 :sha-256 :sha-512}.

    For multi-arg content: concatenates all content then hashes the
    concatenation once.

    Less computationally expensive than `hash-ba-cascade`, but also less
    resistant to length-extension attacks, etc."
    (^bytes [hash-algo           ] (.digest (as-message-digest hash-algo)                ba0))
    (^bytes [hash-algo ba-content] (.digest (as-message-digest hash-algo) (or ba-content ba0)))
    (^bytes [hash-algo ba-content & more]
     (let [md (as-message-digest hash-algo)]
       (when-let [bac ba-content]  (.update md ^bytes bac))
       (doseq [bac more] (when bac (.update md ^bytes bac)))
       (do                         (.digest md))))))

(let [ba0 (byte-array 0)]
  (defn hash-ba-cascade
    "Returns hash digest of given byte[] ?content.
    Takes `hash-algo` ∈ #{:md5 :sha-1 :sha-256 :sha-512}.

    For multi-arg content: hashes each individual arg, concatenates the
    hashes, then hashes the concatenation.

    More computationally expensive than `hash-ba-concat`, but also more
    resistant to length-extension attacks, etc."
    ^bytes [hash-algo & ba-content]
    (let [md     (as-message-digest hash-algo)
          hashes (mapv #(.digest md (or % ba0)) ba-content)
          joined (bytes/ba-join* hashes)]
      (.digest md joined))))

(comment (vec (hash-ba-cascade :sha-256 (as-ba "1") (as-ba "2"))))

(enc/defaliases
  {:alias hash-ba, :src hash-ba-cascade, :doc "Alias for `hash-ba-cascade`"})

;;;; HMAC (Hash-based Message Authentication Code)
;; Concept: hash the combination of shared secret (e.g. key) and some content.
;; Note that HMAC can also be used as part of HKDF (RFC 5869), in which case
;; an optional/zeroed salt is used as shared secret.

(let [hmac-md5_     (enc/thread-local (javax.crypto.Mac/getInstance "HmacMD5"))
      hmac-sha-1_   (enc/thread-local (javax.crypto.Mac/getInstance "HmacSHA1"))
      hmac-sha-256_ (enc/thread-local (javax.crypto.Mac/getInstance "HmacSHA256"))
      hmac-sha-512_ (enc/thread-local (javax.crypto.Mac/getInstance "HmacSHA512"))]

  (defn- as-hmac
    "Returns `javax.crypto.Mac`, or throws.
    Takes `hash-algo` ∈ #{:md5 :sha-1 :sha-256 :sha-512}."
    ^javax.crypto.Mac [hash-algo]
    (case hash-algo
      :md5     @hmac-md5_
      :sha-1   @hmac-sha-1_
      :sha-256 @hmac-sha-256_
      :sha-512 @hmac-sha-512_
      (enc/unexpected-arg! hash-algo
        {:expected #{:md5 :sha-1 :sha-256 :sha-512}
         :context  `as-hmac}))))

(defn hmac
  "Returns HMAC of given non-empty byte[] secret and non-empty byte[] content.
  Takes `hash-algo` ∈ #{:md5 :sha-1 :sha-256 :sha-512}.

  Has several uses, including derive additional keys from secret:
    (hmac :sha-256 ba-secret ba-label1), etc."

  (^bytes [hash-algo ba-secret ba-content]
   (have? bytes/nempty-ba? ba-secret ba-content)
   (let [hmac     (as-hmac hash-algo)
         key-spec (javax.crypto.spec.SecretKeySpec. ba-secret (.getAlgorithm hmac))]
     (.init    hmac key-spec)
     (.doFinal hmac ba-content)))

  (^bytes [hash-algo ba-secret ba-content & more]
   (have? bytes/nempty-ba? ba-secret)
   (let [hmac     (as-hmac hash-algo)
         key-spec (javax.crypto.spec.SecretKeySpec. ba-secret (.getAlgorithm hmac))
         content? (volatile! false)]

     (.init hmac key-spec)

     (when-let [bac (bytes/nempty-ba ba-content)]
       (.update hmac ^bytes bac)
       (vreset! content? true))

     (doseq [bac more]
       (when-let [bac (bytes/nempty-ba bac)]
         (.update hmac ^bytes bac)
         (vreset! content? true)))

     (if @content?
       (.doFinal hmac)
       (throw (ex-info "HMAC needs >0 content length" {}))))))

(let [ba-dummy (byte-array [0 1 2 3 4 5 6 7])
      cached   (enc/fmemoize #(alength (hmac % ba-dummy ba-dummy)))]

  (defn hmac-len
    "Returns byte[] length of the output generated by `hmac` when using the
    given `hash-algo`."
    ^long [hash-algo] (cached hash-algo)))

;;;; Symmetric ciphers (AES, etc.)

(def ^:const default-sym-key-len "256 bits" 32)
(def ^:const min-iv-len          "128 bits" 16)

(let [cipher-aes-gcm_    (enc/thread-local (javax.crypto.Cipher/getInstance "AES/GCM/NoPadding"))
      cipher-aes-cbc_    (enc/thread-local (javax.crypto.Cipher/getInstance "AES/CBC/PKCS5Padding"))
      chacha20-poly1305_ (enc/thread-local (javax.crypto.Cipher/getInstance "ChaCha20-Poly1305"))]

  (defn- as-symmetric-cipher
    "Returns `javax.crypto.Cipher`, or throws.
    Takes `sym-cipher-algo` ∈ #{:aes-gcm :aes-cbc :chacha20-poly1305}."
    ^javax.crypto.Cipher [sym-cipher-algo]
    (case sym-cipher-algo
      :aes-gcm @cipher-aes-gcm_
      :aes-cbc @cipher-aes-cbc_
      :chacha20-poly1305 @chacha20-poly1305_
      (enc/unexpected-arg! sym-cipher-algo
        {:expected #{:aes-gcm :aes-cbc :chacha20-poly1305}
         :context  `as-symmetric-cipher}))))

(defprotocol ISymmetricCipherKit
  "Private protocol, lowest level symmetric API. Zero enveloping."
  (       sck-kid      [_])
  (       sck-can-aad? [_])
  (^bytes sck-encrypt  [_ ba-iv ba-key ba-content           ?ba-aad] "=> ba-encrypted-content")
  (^bytes sck-decrypt  [_ ba-iv ba-key ba-encrypted-content ?ba-aad] "=> ba-content-decrypted")
  (^long  sck-key-len  [_])
  (^long  sck-iv-len   [_]))

(deftype SymmetricCipherKit-aes-gcm-v1
  [^int key-len ^int iv-len ^int auth-tag-nbits]

  ISymmetricCipherKit
  (sck-kid      [_] :aes-gcm-v1)
  (sck-can-aad? [_] true)
  (sck-key-len  [_] key-len)
  (sck-iv-len   [_] iv-len)
  (sck-encrypt  [_ ba-iv ba-key ba-content ?ba-aad]
    (let [cipher     (as-symmetric-cipher :aes-gcm)
          ba-key     (bytes/ba->sublen key-len ba-key)
          ba-iv      (bytes/ba->sublen iv-len  ba-iv)
          key-spec   (javax.crypto.spec.SecretKeySpec. ba-key "AES")
          param-spec (javax.crypto.spec.GCMParameterSpec. auth-tag-nbits ba-iv)]

      (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key-spec param-spec)
      (when-let [^bytes ba-aad ?ba-aad] (.updateAAD cipher ba-aad))

      (.doFinal cipher ba-content)))

  (sck-decrypt [_ ba-iv ba-key ba-encrypted-content ?ba-aad]
    (let [cipher     (as-symmetric-cipher :aes-gcm)
          ba-key     (bytes/ba->sublen key-len ba-key)
          ba-iv      (bytes/ba->sublen iv-len  ba-iv)
          key-spec   (javax.crypto.spec.SecretKeySpec. ba-key "AES")
          param-spec (javax.crypto.spec.GCMParameterSpec. auth-tag-nbits ba-iv)]

      (.init cipher javax.crypto.Cipher/DECRYPT_MODE key-spec param-spec)
      (when-let [^bytes ba-aad ?ba-aad] (.updateAAD cipher ba-aad))

      (.doFinal cipher ba-encrypted-content))))

(defn- ensure-no-aad! [sck ?ba-aad]
  (when-let [^bytes ba-aad ?ba-aad]
    (when (pos?    (alength ba-aad))
      (throw
        (ex-info "AAD not supported for cipher"
          {:cipher (sck-kid sck)})))))

(deftype SymmetricCipherKit-aes-cbc-v1-deprecated
  [^int key-len ^int iv-len]

  ;; Deprecated since:
  ;;   - Doesn't support AAD.
  ;;   - Doesn't include MAC, so cannot verify key before attempting decryption.
  ;;   - GCM mode generally preferred (faster, more secure, includes MAC, etc.).

  ;; Could (but not bothering to) write a v2 kit with manual AAD and MAC, e.g.:
  ;;   - On encrypt:
  ;;     - Add MAC to ciphertext = (hmac ba-derived-key (+ ba-iv ba-encrypted-content ?ba-aad))
  ;;       - Where ba-derived-key is something like (hmac ba-key ba-const-auth) or (hmac ba-key ba-iv), etc.
  ;;   - On decrypt: regen MAC and compare to MAC w/in envelope to provide protection against:
  ;;     1. Attempting decryption with wrong key
  ;;     2. Accidental  data/aad corruption
  ;;     3. Intentional data/aad manipulation (attacker cannot regen MAC without ba-key)

  ISymmetricCipherKit
  (sck-kid      [_] :aes-cbc-v1-deprecated)
  (sck-can-aad? [_] false)
  (sck-key-len  [_] key-len)
  (sck-iv-len   [_] iv-len)
  (sck-encrypt  [sck ba-iv ba-key ba-content ?ba-aad]
    (let [cipher     (as-symmetric-cipher :aes-cbc)
          ba-key     (bytes/ba->sublen key-len ba-key)
          ba-iv      (bytes/ba->sublen iv-len  ba-iv)
          key-spec   (javax.crypto.spec.SecretKeySpec. ba-key "AES")
          param-spec (javax.crypto.spec.IvParameterSpec. ba-iv)]

      (ensure-no-aad! sck ?ba-aad)
      (.init    cipher javax.crypto.Cipher/ENCRYPT_MODE key-spec param-spec)
      (.doFinal cipher ba-content)))

  (sck-decrypt [sck ba-iv ba-key ba-encrypted-content ?ba-aad]
    (let [cipher     (as-symmetric-cipher :aes-cbc)
          ba-key     (bytes/ba->sublen key-len ba-key)
          ba-iv      (bytes/ba->sublen iv-len  ba-iv)
          key-spec   (javax.crypto.spec.SecretKeySpec. ba-key "AES")
          param-spec (javax.crypto.spec.IvParameterSpec. ba-iv)]

      (ensure-no-aad! sck ?ba-aad)
      (.init    cipher javax.crypto.Cipher/DECRYPT_MODE key-spec param-spec)
      (.doFinal cipher ba-encrypted-content))))

(deftype SymmetricCipherKit-chacha20-poly1305-v1
  [^int key-len ^int iv-len]

  ISymmetricCipherKit
  (sck-kid      [_] :chacha20-poly1305-v1)
  (sck-can-aad? [_] true)
  (sck-key-len  [_] key-len)
  (sck-iv-len   [_] iv-len)
  (sck-encrypt  [_ ba-iv ba-key ba-content ?ba-aad]
    (let [cipher     (as-symmetric-cipher :chacha20-poly1305)
          ba-key     (bytes/ba->sublen key-len ba-key)
          ba-iv      (bytes/ba->sublen iv-len  ba-iv)
          key-spec   (javax.crypto.spec.SecretKeySpec. ba-key "ChaCha20")
          param-spec (javax.crypto.spec.IvParameterSpec. ba-iv)]

      (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key-spec param-spec)
      (when-let [^bytes ba-aad ?ba-aad] (.updateAAD cipher ba-aad))

      (.doFinal cipher ba-content)))

  (sck-decrypt [_ ba-iv ba-key ba-encrypted-content ?ba-aad]
    (let [cipher     (as-symmetric-cipher :chacha20-poly1305)
          ba-key     (bytes/ba->sublen key-len ba-key)
          ba-iv      (bytes/ba->sublen iv-len  ba-iv)
          key-spec   (javax.crypto.spec.SecretKeySpec. ba-key "ChaCha20")
          param-spec (javax.crypto.spec.IvParameterSpec. ba-iv)]

      (when (< (enc/java-version) 21)
        ;; Java <21 cipher has a bug that prevents sequential reuse of the same IV even when
        ;; decrypting. That unintentionally prevents legitimate use cases like decrypting right after
        ;; encrypting, etc. We work around this when necessary by first doing a dummy init with a
        ;; unique (bit-flipped) IV. Ref. <https://bugs.openjdk.org/browse/JDK-8305091>
        (let [dummy-ba-iv      (doto (aclone ba-iv) (aset-byte 0 (bit-flip (aget ba-iv 0) 0)))
              dummy-param-spec (javax.crypto.spec.IvParameterSpec. dummy-ba-iv)]
          (.init cipher javax.crypto.Cipher/DECRYPT_MODE key-spec dummy-param-spec)))

      (.init cipher javax.crypto.Cipher/DECRYPT_MODE key-spec param-spec)
      (when-let [^bytes ba-aad ?ba-aad] (.updateAAD cipher ba-aad))

      (.doFinal cipher ba-encrypted-content))))

(let [;; Ref. NIST SP800-38D §5.2.1.1 for params
      sck-aes-gcm-128-v1 (SymmetricCipherKit-aes-gcm-v1. 16 12 128)
      sck-aes-gcm-192-v1 (SymmetricCipherKit-aes-gcm-v1. 24 12 128)
      sck-aes-gcm-256-v1 (SymmetricCipherKit-aes-gcm-v1. 32 12 128)

      sck-aes-cbc-128-v1-deprecated (SymmetricCipherKit-aes-cbc-v1-deprecated. 16 16)
      sck-aes-cbc-256-v1-deprecated (SymmetricCipherKit-aes-cbc-v1-deprecated. 32 16)
      sck-chacha20-poly1305-v1      (SymmetricCipherKit-chacha20-poly1305-v1.  32 12) ; 256 bit only

      expected
      #{:aes-gcm-128-v1
        :aes-gcm-192-v1
        :aes-gcm-256-v1
        :aes-cbc-128-v1-deprecated
        :aes-cbc-256-v1-deprecated
        :chacha20-poly1305-v1}]

  (defn as-symmetric-cipher-kit
    "Returns `ISymmetricCipherKit` implementer, or throws.
    Takes `sym-cipher-algo` ∈ #{:aes-gcm-<nbits>-v1 :aes-cbc-<nbits>-v1-deprecated :chacha20-poly1305-v1}."
    [sym-cipher-algo]
    (if (keyword? sym-cipher-algo)
      (case       sym-cipher-algo
        :aes-gcm-128-v1            sck-aes-gcm-128-v1
        :aes-gcm-192-v1            sck-aes-gcm-192-v1
        :aes-gcm-256-v1            sck-aes-gcm-256-v1

        :aes-cbc-128-v1-deprecated sck-aes-cbc-128-v1-deprecated
        :aes-cbc-256-v1-deprecated sck-aes-cbc-256-v1-deprecated

        :chacha20-poly1305-v1      sck-chacha20-poly1305-v1

        (enc/unexpected-arg! sym-cipher-algo
          {:expected expected
           :context  `as-symmetric-cipher-kit}))

      (enc/satisfies! ISymmetricCipherKit sym-cipher-algo
        {:expected expected
         :context  `as-symmetric-cipher-kit}))))

;;;; Asymmetric crypto

(defn- key-algo-unknown! [x context]
  (enc/unexpected-arg! x
    {:context context
     :expected
     #{:symmetric
       :rsa :rsa-<nbits>
       :dh  :dh-<nbits>
       :ec  :ec-<curve>}}))

(defn key-algo-info
  "Returns ?{:keys [kf-algo ka-algo sig-algo cipher-algo, asymmetric? symmetric? wild?]}.

  Capabilities exist iff {:keys [ka-algo sig-algo sym-cipher-algo asym-cipher-algo]} do.
  These specify the default algo for each corresponding capability."
  [key-algo]
  (case key-algo
    :symmetric {:symmetric?  true, :sym-cipher-algo :aes-gcm-128-v1}
    :rsa       {:asymmetric? true, :wild? true, :kf-algo :rsa}
    :dh        {:asymmetric? true, :wild? true, :kf-algo :dh}
    :ec        {:asymmetric? true, :wild? true, :kf-algo :ec}

    (:rsa-1024 :rsa-2048 :rsa-3072 :rsa-4096)
    {:kf-algo          :rsa
     ;; :ka-algo       nil
     :sig-algo         :sha-256-rsa
     :asym-cipher-algo :rsa-oaep-sha-256-mgf1
     :asymmetric?      true}

    (:dh-1024 :dh-2048 :dh-3072 :dh-4096)
    {:kf-algo             :dh
     :ka-algo             :dh
     ;; :sig-algo         nil
     ;; :asym-cipher-algo nil
     :asymmetric?         true}

    (:ec-secp256r1 :ec-secp384r1 :ec-secp521r1)
    {:kf-algo             :ec
     :ka-algo             :ecdh
     :sig-algo            :sha-256-ecdsa
     ;; :asym-cipher-algo nil
     :asymmetric?         true}

    #_(key-algo-unknown! key-algo)
    nil))

(comment (key-algo-info :ec-secp256r1))

(defn key-algo?
  "Returns given `key-algo` matching needs, or nil."
  ([key-algo      ] (when (key-algo-info key-algo) key-algo))
  ([key-algo needs]
   (when-let [m-info (key-algo-info key-algo)]
     (when (enc/revery? m-info needs)
       key-algo))))

(comment (key-algo? :dh-1024 [:asymmetric? :ka-algo]))

(defn key-algo!
  "Returns given `key-algo` matching needs, or throws."
  ([key-algo      ] (if (key-algo? key-algo) key-algo (key-algo-unknown! key-algo `key-algo!)))
  ([key-algo needs]
   (if-let [m-info (key-algo-info key-algo)]
     (do
       (doseq [need needs]
         (when-not (get m-info need)
           (throw
             (case need
               :symmetric?       (ex-info "Unexpected key algorithm: need symmetric type"            {:key-algo         key-algo, :type {:actual :asymmetric, :expected :symmetric}})
               :asymmetric?      (ex-info "Unexpected key algorithm: need asymmetric type"           {:key-algo         key-algo, :type {:actual :symmetric,  :expected :asymmetric}})
               :sig-algo         (ex-info "Unexpected key algorithm: need signature support"         {:key-algo {:given key-algo, :expected #{:rsa-<nbits> :ec-<curve>}}})
               :ka-algo          (ex-info "Unexpected key algorithm: need key agreement support"     {:key-algo {:given key-algo, :expected #{:dh-<nbits>  :ec-<curve>}}}) 
               :asym-cipher-algo (ex-info "Unexpected key algorithm: need asymmetric cipher support" {:key-algo {:given key-algo, :expected #{:rsa-<nbits>}}})
               (do               (ex-info "Unexpected key algorithm: doesn't meet need"              {:key-algo         key-algo, :need need}))))))
       key-algo)

     (key-algo-unknown! key-algo `key-algo!))))

(comment
  (key-algo! :dh-1024 [:asymmetric? :ka-algo])
  (key-algo! :dh-1024 [:asymmetric? :sig-algo]))

(defn key-algo= [key-algo1 key-algo2]
  (or
    (enc/identical-kw? key-algo1 key-algo2)
    (let [info1 (key-algo-info key-algo1)
          info2 (key-algo-info key-algo2)]
      (and
        (or                (get info1 :wild?)   (get info2 :wild?))
        (enc/identical-kw? (get info1 :kf-algo) (get info2 :kf-algo))))
    false))

(comment
  [(key-algo= :rsa      :rsa-1024)
   (key-algo= :rsa-1024 :rsa-2048)])

;;;;

(defn- kpg-get [algo-name algo-params]
  (have? string? algo-name)
  (let [kpg (java.security.KeyPairGenerator/getInstance algo-name)
        sr  (srng)]

    (enc/cond
      (int?     algo-params) (.initialize kpg (int algo-params) sr)
      (keyword? algo-params)
      (case     algo-params
        :ec-secp256r1 (.initialize kpg (java.security.spec.ECGenParameterSpec. "secp256r1") sr) ; NIST-P-256
        :ec-secp384r1 (.initialize kpg (java.security.spec.ECGenParameterSpec. "secp384r1") sr) ; NIST-P-384
        :ec-secp521r1 (.initialize kpg (java.security.spec.ECGenParameterSpec. "secp521r1") sr) ; NIST-P-521

        (enc/unexpected-arg! algo-params
          {:expected #{:ec-secp256-r1}
           :context  `kpg-get}))

      :else
      (.initialize kpg ^java.security.spec.AlgorithmParameterSpec algo-params sr))

    kpg))

(let [;; Avoid thread-locals here since we want fresh *srng*
      ;; kpb-get*
      ;; (fn [algo-name algo-params]
      ;;   (enc/thread-local (kpg-get algo-name algo-params)))
      ;;
      ;; kpg-rsa-1024_ (kpg-get* "RSA" 1024) ; etc.
      ]

  (defn- as-keypair-generator
    "Returns `java.security.KeyPairGenerator`, or throws.
    Takes `key-algo` ∈ #{:rsa-<nbits> :dh-<nbits> :ec-<curve>}."
    ^java.security.KeyPairGenerator [key-algo]
    (case key-algo
      ;; :rsa-1024  @kpg-rsa-1024_
      :rsa-1024     (kpg-get "RSA" 1024)
      :rsa-2048     (kpg-get "RSA" 2048)
      :rsa-3072     (kpg-get "RSA" 3072)
      :rsa-4096     (kpg-get "RSA" 4096)

      :dh-1024      (kpg-get "DH"  1024)
      :dh-2048      (kpg-get "DH"  2048)
      :dh-3072      (kpg-get "DH"  3072)
      :dh-4096      (kpg-get "DH"  4096)

      :ec-secp256r1 (kpg-get "EC" :ec-secp256r1)
      :ec-secp384r1 (kpg-get "EC" :ec-secp384r1)
      :ec-secp521r1 (kpg-get "EC" :ec-secp521r1)

      (enc/unexpected-arg! key-algo
        {:expected #{:rsa-<nbits> :dh-<nbits> :ec-<curve>}
         :context  `as-keypair-generator}))))

(defn ^:public keypair-create
  "Generates and returns a new `java.security.KeyPair` for given
  `key-algo` ∈ #{:rsa :rsa-<nbits> :dh :dh-<nbits> :ec-<curve>}.

  Slow! Consider instead using `keypair-creator`."
  (^java.security.KeyPair [key-algo needs] (keypair-create (key-algo! key-algo needs)))
  (^java.security.KeyPair [key-algo      ]
   (let [kpg (as-keypair-generator key-algo)]
     (.generateKeyPair kpg))))

(defn ^:public keypair-creator
  "Returns a stateful (fn keypair-get [key-algo]) like `keypair-create` that
  eagerly pre-computes keypairs of all previously-requested algos.

  Compare:
    (keypair-create :rsa-2048) ; Slow, keypair generated on demand
    ;; vs
    (defonce kpc (keypair-create {:buffer-len 128, :n-threads [:perc 10]}))
    (kpc :rsa-2048) ; Slow first call, keypair generated on demand
    (kpc :rsa-2048) ; Fast subsequent calls, will use cache of up to
                    ; 128 pre-generated keypairs"
  [&
   [{:keys [buffer-len n-threads]
     :or   {buffer-len 16
            n-threads  [:perc 10]}}]]

  (let [fns_ (atom {}) ; {<key-algo> (fn keypair-get [])}
        shared-fp (enc/future-pool n-threads)]

    (fn keypair-get
      ([key-algo needs] (keypair-get (key-algo! key-algo needs)))
      ([key-algo      ]
       (let [fn_
             (enc/swap-val! fns_ key-algo
               (fn [?fn_]
                 (or
                   ?fn_
                   (delay
                     (enc/pre-cache buffer-len shared-fp
                       (fn keypair-get [] (keypair-create key-algo)))))))]
         (@fn_))))))

(defn keypair-create*
  "Like `keypair-create` but returns {:keys [keypair key-prv key-pub ba-prv ba-pub ...]}."
  ([key-algo needs] (keypair-create* (key-algo! key-algo needs)))
  ([key-algo      ]
   (let [kp (keypair-create key-algo) ; java.security.KeyPair
         key-prv (.getPrivate kp)     ; java.security.Key
         key-pub (.getPublic  kp)     ; java.security.Key
         ]

     {:key-algo               key-algo
      :keypair                      kp
      :key-prv                 key-prv
      :key-pub                 key-pub
      :ba-prv     (.getEncoded key-prv)
      :ba-pub     (.getEncoded key-pub)
      ;; :fmt-prv (.getFormat  key-prv)
      ;; :fmt-pub (.getFormat  key-pub)
      })))

(comment
  (keypair-create :rsa-1024 )
  (keypair-create :rsa-1024 [:sig-algo])

  (enc/qb 10 ; [953.16 5.16 4.61]
    (keypair-create :rsa-2048)
    (keypair-create :dh-2048)
    (keypair-create :ec-secp256r1))

  (let [kpc (keypair-creator)]
    (kpc :rsa-2048) ; Trigger pre-cache
    (Thread/sleep 2000) ; Warm-up
    (enc/qb 10 ; [795.2 3.02]
      (keypair-create :rsa-2048)
      (kpc            :rsa-2048)))

  (with-srng-insecure-deterministic!!! 10
    (vec (:ba-pub (keypair-create* :rsa-2048)))))

;;;;

(defprotocol IKeyPair
  (^:private -keypair-info [x] "Returns ?{:keys [key-algo key-prv key-pub]}"))

(defn- keypair-info-rsa [^java.security.interfaces.RSAKey key]
  (let [n-bits  (.bitLength (.getModulus key))
        key-algo (keyword (str "rsa-" n-bits))]
    {:key-algo key-algo}))

(defn- keypair-info-dh [^javax.crypto.interfaces.DHKey key]
  (let [n-bits  (.bitLength (.getP (.getParams key)))
        key-algo (keyword (str "dh-" n-bits))]
    {:key-algo key-algo}))

(defn- ec-params [^java.security.interfaces.ECKey key]
  (let [curve (.getCurve (.getParams key))]
    [(let [f (.getField curve)]
       (when (instance? java.security.spec.ECFieldFp f)
         (.getP ^java.security.spec.ECFieldFp f)))
     (.getA curve)
     (.getB curve)]))

(comment (ec-params (:key-prv (keypair-create* :ec-secp256r1))))

(defn- keypair-info-ec [^java.security.interfaces.ECKey key]
  ;; Unfortunately the only way to identify a curve is via its field+coefficients
  (let [key-algo
        (case (ec-params key)
          [115792089210356248762697446949407573530086143415290314195533631308867097853951N
           115792089210356248762697446949407573530086143415290314195533631308867097853948N
           41058363725152142129326129780047268409114441015993725554835256314039467401291N]
          :ec-secp256r1

          [39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319N
           39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316N
           27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575N]
          :ec-secp384r1

          [6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151N
           6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148N
           1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984N]
          :ec-secp521r1

          (throw
            (ex-info "Unexpected `java.security.interfaces.ECKey` curve"
              {:expected #{:ec-secp256-r1 :ec-secp384r1 :ec-secp521r1}
               :context  `keypair-info-ec})))]

    {:key-algo key-algo}))

(comment (keypair-info-ec (:key-prv (keypair-create* :ec-secp256r1))))

(extend-protocol IKeyPair
  java.security.interfaces.RSAPrivateKey (-keypair-info [x] (assoc (keypair-info-rsa x) :key-prv x))
  java.security.interfaces.RSAPublicKey  (-keypair-info [x] (assoc (keypair-info-rsa x) :key-pub x))
  javax.crypto.interfaces.DHPrivateKey   (-keypair-info [x] (assoc (keypair-info-dh  x) :key-prv x))
  javax.crypto.interfaces.DHPublicKey    (-keypair-info [x] (assoc (keypair-info-dh  x) :key-pub x))
  java.security.interfaces.ECPrivateKey  (-keypair-info [x] (assoc (keypair-info-ec  x) :key-prv x))
  java.security.interfaces.ECPublicKey   (-keypair-info [x] (assoc (keypair-info-ec  x) :key-pub x))
  java.security.KeyPair
  (-keypair-info [x]
    (let [{key-algo-prv :key-algo, :as info-prv} (-keypair-info (.getPrivate x))
          {key-algo-pub :key-algo, :as info-pub} (-keypair-info (.getPublic  x))]

      (if (and key-algo-prv key-algo-pub (not= key-algo-prv key-algo-pub))
        (throw
          (ex-info "Unmatched `java.security.KeyPair` algorithms"
            {:key-algos {:private key-algo-prv, :public key-algo-prv}}))

        (merge info-prv info-pub))))

  nil    (-keypair-info [_] nil)
  Object (-keypair-info [_] nil))

(comment
  (keypair-info (java.security.KeyPair. nil nil))
  (keypair-info
    (java.security.KeyPair.
      (:key-pub (keypair-create* :rsa-1024))
      (:key-prv (keypair-create* :rsa-2048)))))

(defn keypair-info
  "Returns ?{:keys [key-algo key-prv key-pub]}"
  [x]
  (when (or
          (instance? java.security.Key     x)
          (instance? java.security.KeyPair x))
    (-keypair-info x)))

(defn keypair-algo [x] (get (keypair-info x) :key-algo))

(comment
  [(keypair-algo (:keypair (keypair-create* :rsa-2048)))
   (keypair-info (:keypair (keypair-create* :rsa-2048)))
   (keypair-info (:key-pub (keypair-create* :rsa-2048)))
   (keypair-info (:key-prv (keypair-create* :rsa-2048)))
   (keypair-info (:keypair (keypair-create*  :dh-2048)))
   (keypair-info (:key-pub (keypair-create*  :dh-2048)))
   (keypair-info (:key-prv (keypair-create*  :dh-4096)))
   (keypair-info (:key-prv (keypair-create* :ec-secp384r1)))
   (keypair-info nil)])

;;;;

(let [kf-rsa_ (enc/thread-local (java.security.KeyFactory/getInstance "RSA"))
      kf-dh_  (enc/thread-local (java.security.KeyFactory/getInstance "DiffieHellman"))
      kf-ec_  (enc/thread-local (java.security.KeyFactory/getInstance "EC"))]

  (defn- as-key-factory
    "Returns `java.security.KeyFactory`, or throws.
    Takes `key-algo` ∈ #{:rsa :rsa-<nbits> :dh :dh-<nbits> :ec-<curve>}."
    ^java.security.KeyFactory
    [key-algo]
    (case key-algo
      (:rsa :rsa-1024 :rsa-2048 :rsa-3072 :rsa-4096)  @kf-rsa_
      (:dh   :dh-1024  :dh-2048  :dh-3072  :dh-4096)  @kf-dh_
      (:ec :ec-secp256r1 :ec-secp384r1 :ec-secp521r1) @kf-ec_

      (enc/unexpected-arg! key-algo
        {:expected #{:rsa :rsa-<nbits> :dh :dh-<nbits> :ec :ec-<curve>}
         :context  `as-key-factory}))))

(let [decode-prv (fn [^java.security.KeyFactory kf ba-prv] (.generatePrivate kf (java.security.spec.PKCS8EncodedKeySpec. ba-prv)))
      decode-pub (fn [^java.security.KeyFactory kf ba-pub] (.generatePublic  kf (java.security.spec.X509EncodedKeySpec.  ba-pub)))]

  (defn as-key
    "Returns `java.security.Key` matching given needs, or throws.
    Takes `key-algo` ∈ #{:rsa :rsa-<nbits> :dh :dh-<nbits> :ec :ec-<curve>}."
    ^java.security.Key [private? ?key-algo ?needs x-key]

    ;; Check if needs are in principle met by given key-algo
    (when (and ?key-algo ?needs) (key-algo! ?key-algo ?needs))

    (let [key-class (if private? java.security.PrivateKey java.security.PublicKey)
          fail!
          (fn [throwable error-data]
            (throw
              (ex-info (str "Failed to prepare expected `" (.getName ^java.lang.Class key-class) "`")
                (enc/assoc-some error-data
                  :given-type (type x-key)
                  :requested-key-algo ?key-algo)
                throwable)))

          key
          (enc/cond
            (instance? java.security.Key     x-key) x-key
            (instance? java.security.KeyPair x-key)
            (if private?
              (.getPrivate ^java.security.KeyPair x-key)
              (.getPublic  ^java.security.KeyPair x-key))

            (enc/bytes? x-key)
            (let [kf (as-key-factory ?key-algo)]
              (try
                (if private?
                  (decode-prv kf x-key)
                  (decode-pub kf x-key))
                (catch Throwable t
                  (fail! t {:error :decode-failure}))))

            :else
            (fail! nil
              {:error :unexpected-key-arg-type
               :type  {:actual   (type x-key)
                       :expected '#{java.security.Key java.security.KeyPair byte-array}}}))

          {:keys [key-algo]} (keypair-info key)]

      (enc/cond
        (not (instance? key-class key))
        (fail! nil
          {:error :key-type-mismatch
           :type  {:actual   (type key)
                   :expected key-class}})

        (and ?key-algo (not (key-algo= ?key-algo key-algo)))
        (fail! nil
          {:error :key-algo-mismatch
           :algo  {:actual    key-algo
                   :expected ?key-algo}})

        :if-let [t (when ?needs (enc/throws (key-algo! key-algo ?needs)))]
        (fail!   t
          {:error        :key-needs-mismatch
           :algo         key-algo
           :capabilities {:actual   (key-algo-info key-algo),
                          :expected ?needs}})

        :else key))))

(defn as-key-pub
  "Returns `java.security.PublicKey`, or throws.
  Takes `key-algo` ∈ #{:rsa :rsa-<nbits> :dh :dh-<nbits> :ec :ec-<curve>}."
  ^java.security.PublicKey [?key-algo ?needs x-pub]
  (as-key false ?key-algo ?needs x-pub))

(defn as-key-prv
  "Returns `java.security.PrivateKey`, or throws.
  Takes `key-algo` ∈ #{:rsa-<nbits> :dh-<nbits> :ec :ec-<curve>}."
  ^java.security.PrivateKey [?key-algo ?needs x-prv]
  (as-key true ?key-algo ?needs x-prv))

(comment
  [(as-key-pub :rsa-2048 nil (:ba-pub  (keypair-create* :rsa-2048)))
   (as-key-pub :rsa      nil (:ba-pub  (keypair-create* :rsa-2048)))
   (as-key-pub nil       nil (:keypair (keypair-create* :rsa-2048)))]
  [(as-key-pub :rsa-1024 nil (:ba-pub  (keypair-create* :rsa-2048)))])

;;;; Asymmetric ciphers using 1 keypair

(let [cipher-rsa-oaep-sha-256-mgf1_
      (enc/thread-local
        (javax.crypto.Cipher/getInstance
          "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"))]

  (defn- as-asymmetric-cipher
    "Returns `javax.crypto.Cipher`, or throws.
    Takes `asym-cipher-algo` ∈ #{:rsa-oaep-sha-256-mgf1}."
    ^javax.crypto.Cipher [asym-cipher-algo]
    (case asym-cipher-algo
      :rsa-oaep-sha-256-mgf1 @cipher-rsa-oaep-sha-256-mgf1_
      (enc/unexpected-arg! asym-cipher-algo
        {:expected #{:rsa-oaep-sha-256-mgf1}
         :context  `as-asymmetric-cipher}))))

(defn encrypt-asymmetric
  "Takes `asym-cipher-algo` ∈ #{:rsa-oaep-sha-256-mgf1}.
  Content length is limited by public key length, so generally used
  only to encrypt a random key for a symmetric cipher."
  ^bytes [asym-cipher-algo key-algo key-pub ba-content]
  (let [cipher  (as-asymmetric-cipher asym-cipher-algo)
        key-pub (as-key-pub key-algo [:asymmetric? :asym-cipher-algo] key-pub)]
    (.init    cipher javax.crypto.Cipher/ENCRYPT_MODE key-pub)
    (.doFinal cipher ba-content)))

(defn decrypt-asymmetric
  "Takes `asym-cipher-algo` ∈ #{:rsa-oaep-sha-256-mgf1}."
  ^bytes [asym-cipher-algo key-algo key-prv ba-encrypted-content]
  (let [cipher  (as-asymmetric-cipher asym-cipher-algo)
        key-prv (as-key-prv key-algo [:asymmetric? :asym-cipher-algo] key-prv)]
    (.init    cipher javax.crypto.Cipher/DECRYPT_MODE key-prv)
    (.doFinal cipher ba-encrypted-content)))

;;;; Asymmetric ciphers using 2 keypairs
;; Note that >2 party key-agreement is possible, but impractical since it
;; needs multiple (combinatorial!) passing of awkward partial agreements
;; between parties.
;;
;; In practice, it's often better (simpler and more flexible) to instead do
;; something like the following for parties `p1` ... `pn`:
;;   - `p1` acts as owner/hub, generates a random key `rk`
;;   - `p1` then shares `rk` with `pi`s using pairwise DH
;;
;;   Note that this also easily supports the addition + removal of
;;   participants (removal => `p1` rotate key).
;;
;;   Ref. <https://stackoverflow.com/a/58993471/1982742>,
;;        <https://crypto.stackexchange.com/a/1026/106804>

(let [ka-dh_       (enc/thread-local (javax.crypto.KeyAgreement/getInstance "DiffieHellman")) ; PKCS #3
      ka-ecdh_     (enc/thread-local (javax.crypto.KeyAgreement/getInstance "ECDH")) ; RFC 3278
      ;; ka-ecmqv_ (enc/thread-local (javax.crypto.KeyAgreement/getInstance "ECMQV"))
      ]

  (defn as-key-agreement
    "Returns `javax.crypto.KeyAgreement`, or throws.
    Takes `ka-algo` ∈ #{:dh :ecdh}."
    ^javax.crypto.KeyAgreement [ka-algo]
    (case ka-algo
      :dh   @ka-dh_
      :ecdh @ka-ecdh_
      (enc/unexpected-arg! ka-algo
        {:expected #{:dh :ecdh}
         :context  `as-key-agreement}))))

(defn key-shared-create
  "Returns the shared key generated by the given key agreement
  protocol and input private and public keys:

    (bytes=
      (key-shared-create :dh participant1-key-prv participant2-key-pub)
      (key-shared-create :dh participant2-key-prv participant1-key-pub))
    => true

  Takes `ka-algo` ∈ #{:dh :ecdh}."
  ^bytes [ka-algo key-algo participant1-key-prv participant2-key-pub]
  (let [ka      (as-key-agreement ka-algo)
        key-prv (as-key-prv key-algo [:asymmetric? :ka-algo] participant1-key-prv)
        key-pub (as-key-pub key-algo [:asymmetric? :ka-algo] participant2-key-pub)]
    (.init           ka key-prv (srng))
    (.doPhase        ka key-pub true)
    (.generateSecret ka)))

;;;; Signatures

(let [sig-sha-256-rsa_   (enc/thread-local (java.security.Signature/getInstance "SHA256withRSA"))
      sig-sha-512-rsa_   (enc/thread-local (java.security.Signature/getInstance "SHA512withRSA"))
      sig-sha-256-ecdsa_ (enc/thread-local (java.security.Signature/getInstance "SHA256withECDSA"))
      sig-sha-512-ecdsa_ (enc/thread-local (java.security.Signature/getInstance "SHA512withECDSA"))]

  (defn- as-signature
    "Returns `java.security.Signature` or throws.
    Takes `sig-algo` ∈ #{:sha-<nbits>-rsa :sha-<nbits>-ecdsa}."
    ^java.security.Signature [sig-algo]
    (case sig-algo
      :sha-256-rsa   @sig-sha-256-rsa_
      :sha-512-rsa   @sig-sha-512-rsa_
      :sha-256-ecdsa @sig-sha-256-ecdsa_
      :sha-512-ecdsa @sig-sha-512-ecdsa_
      (enc/unexpected-arg! sig-algo
        {:expected #{:sha-<nbits>-rsa :sha-<nbits>-ecdsa}
         :context  `as-signature}))))

(defn signature-create
  "Returns the signature created by signing the given content with the
  given private key.

  Takes `sig-algo` ∈ #{:sha-<nbits>-rsa :sha-<nbits>-ecdsa}."
  ^bytes [sig-algo key-algo signer-key-prv ba-content]
  (let [sig            (as-signature sig-algo)
        signer-key-prv (as-key-prv key-algo [:asymmetric? :sig-algo] signer-key-prv)]

    (.initSign sig signer-key-prv)
    (.update   sig ^bytes ba-content)
    (.sign     sig)))

(defn signature-verify
  "Returns true iff the given signature was created by signing the given
    content with the private key corresponding to the given public key.

    I.e. verifies if the keypair owner signed this content.

    Takes `sig-algo` ∈ #{:sha-256-rsa :sha-512-rsa}."
  [sig-algo key-algo signer-key-pub ba-content ba-signature]
  (let [sig            (as-signature sig-algo)
        signer-key-pub (as-key-pub   key-algo [:asymmetric? :sig-algo] signer-key-pub)]

    (.initVerify sig signer-key-pub)
    (.update     sig ^bytes ba-content)
    (.verify     sig ^bytes ba-signature)))

;;;; Derived keys, etc.

(do
  ;; Random 512 bit consts generated with (vec (rand-ba 64))
  (def ^:private const-ba-derive-iv->salt    (byte-array [74 60 68 101 58 -66 110 -53 44 -85 96 27 122 37 105 -3 -96 125 62 -106 121 -116 58 38 87 29 120 -99 84 7 -93 -42 -118 61 -67 19 -110 -26 -33 -123 -24 -79 89 -58 -62 45 118 14 6 42 -119 -79 -49 10 88 80 10 -105 15 -26 67 3 20 0]))
  (def ^:private const-ba-derive-key0->key1  (byte-array [31 69 -48 -116 116 122 -87 -112 -49 16 43 -76 58 117 116 -113 124 53 -76 113 104 28 103 36 8 -11 -3 -34 -78 63 18 -5 -120 17 -47 -101 81 -90 -100 -24 -83 -53 46 78 -36 75 118 122 -111 27 -6 -83 -15 107 -52 20 -76 -77 3 124 1 -70 -47 -46]) )
  (def ^:private const-ba-derive-key1->key2  (byte-array [-20 79 35 72 -46 -91 -11 -32 -26 -67 -102 102 -77 103 -74 94 26 -20 1 11 66 -26 74 87 -68 -119 -68 -122 -92 51 -87 80 -12 -78 109 -58 -9 59 -41 -31 -81 -1 36 -18 5 -54 25 50 -75 4 45 -24 -109 98 -73 -61 -18 59 96 -91 77 -75 -32 -41]))
  (def ^:private const-ba-derive-key1->ehmac (byte-array [-126 3 -69 42 -54 125 -116 -30 20 -64 -96 -16 24 80 22 112 -57 25 -68 25 81 113 9 -105 -25 40 37 95 75 -11 41 30 -120 98 -74 -106 -36 96 54 126 52 -26 3 97 -86 -101 -41 -36 107 9 93 119 59 -32 -79 -100 -81 41 36 69 125 -14 -26 26])))

(do
  (defn derive-ba-salt  "ba-iv -> ba-salt"                 ^bytes [hash-algo ba-iv               ] (hmac hash-algo ba-iv                const-ba-derive-iv->salt))
  (defn derive-ba-key1  "User/password key (key0) -> key1" ^bytes [hash-algo ba-key0 ba-iv ba-akm] (hmac hash-algo ba-key0 ba-iv ba-akm const-ba-derive-key0->key1))
  (defn derive-ba-ehmac "key1 -> embedded HMAC"            ^bytes [hash-algo ba-key1 ba-iv ba-cnt] (hmac hash-algo ba-key1 ba-iv ba-cnt const-ba-derive-key1->ehmac))
  (defn derive-ba-key2  "key1 -> final key (key2)"         ^bytes [hash-algo ba-key1 ba-iv       ] (hmac hash-algo ba-key1 ba-iv        const-ba-derive-key1->key2)))

(defn write-ehmac
  "Generates HMAC of output stream's content up to this point, and writes
  it to stream."
  [out ^java.io.ByteArrayOutputStream baos embed-hmac? hash-algo ba-key1 ba-iv]
  (if-not embed-hmac?
    (bytes/write-dynamic-ba out nil)
    (let [ba-to-hash (.toByteArray baos) ; Hash all content so far
          ba-ehmac   (derive-ba-ehmac hash-algo ba-key1 ba-iv ba-to-hash)]
      (bytes/write-dynamic-ba out ba-ehmac))))

(defn read-ehmac*
  "Returns [idx-ehmac ?ba-ehmac]"
  [in ^java.io.ByteArrayInputStream bais ^bytes ba-in]
  (let [idx-ehmac (- (alength ba-in) (.available bais)) ; Current pos in `ba-in`
        ?ba-ehmac (bytes/read-dynamic-?ba in)]
    [idx-ehmac ?ba-ehmac]))

(defn ehmac-pass?
  "Generates HMAC of output stream's content up to embedded HMAC, and compares
  to the embedded HMAC. Returns true iff the two match."
  [ehmac* ba-in hash-algo ba-key1 ba-iv]
  (let [[idx-ehmac ?ba-ehmac] ehmac*]
    (if-let [ba-ehmac-ref ?ba-ehmac]
      (let [ba-to-hash (bytes/ba->sublen idx-ehmac ba-in)
            ba-ehmac   (derive-ba-ehmac hash-algo ba-key1 ba-iv ba-to-hash)]
        (enc/ba= ba-ehmac-ref ba-ehmac))
      true)))

;;;; Common error messages

(do
  (def ^:const error-msg-bad-backup-key "Failed to decrypt Tempel data (with backup key)")
  (def ^:const error-msg-bad-pwd        "Failed to decrypt Tempel data (with password)")
  (def ^:const error-msg-bad-ehmac      "Unexpected HMAC: bad decryption key, or corrupt data."))
