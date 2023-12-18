(ns ^:no-doc taoensso.tempel.keys
  "Private ns, implementation detail.
  Key management stuff, supports the changing of algos and/or keys over time."
  (:require
   [taoensso.encore       :as enc  :refer [have have?]]
   [taoensso.encore.bytes :as bytes]
   [taoensso.tempel.df    :as df]
   [taoensso.tempel.impl  :as impl]
   [taoensso.tempel.pbkdf :as pbkdf]))

(comment
  (remove-ns 'taoensso.tempel.keys)
  (:api (enc/interns-overview)))

(enc/declare-remote
  taoensso.tempel/get-opts+
  taoensso.tempel/encrypt-with-1-keypair
  taoensso.tempel/decrypt-with-1-keypair)

(alias 'core 'taoensso.tempel)

;;;; Backup keys

(defn get-backup-key-for-encryption
  "Returns nil, or encrypted symmetric backup key (`?ba-ekey1b`).
  This is a 1kp-encrypted copy of `ba-key1`, the (post-AKM!) key from which
  final `ba-key2` will be derived:
    1. (hmac ba-key0 + AKM, etc.) -> `ba-key1`
    2. (1kp-decrypt ?ba-ekey1b)   -> `ba-key1`"
  [ba-key1 encrypt-opts]
  (let [{:keys [backup-key backup-opts]} encrypt-opts]
    (when backup-key
      (let [backup-opts
            (let [base-opts
                  (->
                    encrypt-opts
                    (dissoc :ba-aad :ba-akm :backup-key)
                    (assoc  :embed-hmac? false :scheme :auto))]
              (core/get-opts+ base-opts backup-opts))]
        (try
          (core/encrypt-with-1-keypair (have enc/bytes? ba-key1) backup-key backup-opts)
          (catch Throwable t
            (throw (ex-info "Failed to enable backup key support during encryption" {} t))))))))

(defn get-backup-key-for-decryption
  "Returns `?ba-key1` or decrypted (symmetric) backup key.
  Complement of `get-backup-key-for-encryption`."
  [?ba-ekey1b decrypt-opts]
  (when-let [^bytes ba-ekey1b ?ba-ekey1b]
    (let [{:keys [backup-key backup-opts]} decrypt-opts]
      (when backup-key
        (let [backup-opts
              (let [base-opts
                    (->
                      decrypt-opts
                      (dissoc :ba-aad :ba-akm :backup-key))]
                (assoc
                  (core/get-opts+ base-opts backup-opts)
                  :return :ba-content))]
          (try
            (core/decrypt-with-1-keypair ba-ekey1b backup-key backup-opts)
            (catch Throwable t
              (throw (ex-info "Failed to decrypt embedded backup key" {} t)))))))))

;;;; ChainKey

(deftype ChainKey [key-type key-algo ?meta ?key-id key-cnt]
  Object
  (equals   [this other] (and (instance? ChainKey other) (impl/cnt= key-cnt (.-key-cnt ^ChainKey other))))
  (hashCode [this]       (impl/cnt-hash key-cnt))
  (toString [this]
    (let [m (select-keys @this [:key-algo :symmetric? :private? :public? :secret? :length])]
      (str "ChainKey[" m " " (enc/ident-hex-str this) "]")))

  clojure.lang.IObj
  (meta     [_  ] ?meta)
  (withMeta [_ m] (ChainKey. (have key-type) (have key-algo) m ?key-id key-cnt))

  clojure.lang.IHashEq (hasheq [this] (impl/cnt-hash key-cnt))
  clojure.lang.IDeref
  (deref [_]
    (conj
      (case key-type
        :sym {:key-type :sym, :key-algo key-algo, :symmetric?  true, :secret? true,                  :key-sym key-cnt, :length (alength ^bytes key-cnt)}
        :prv {:key-type :prv, :key-algo key-algo, :asymmetric? true, :secret? true,  :private? true, :key-prv key-cnt}
        :pub {:key-type :pub, :key-algo key-algo, :asymmetric? true, :secret? false, :public?  true, :key-pub key-cnt}
        (enc/unexpected-arg! key-type {:expected #{:sym :pub :prv}}))

      (enc/assoc-some {:key-cnt key-cnt} :key-id ?key-id))))

(enc/deftype-print-methods              ChainKey)
(defn ^:public chainkey? [x] (instance? ChainKey x))

(defn- -chainkey [key-type ?key-algo ?needs ?key-id x-key]
  (let [fail!
        (fn [cause]
          (throw
            (ex-info "Failed to prepare appropriate `ChainKey`"
              (enc/assoc-some
                {:key-type key-type, :x-key {:value 'redacted, :type (type x-key)}}
                :needs    ?needs
                :key-algo ?key-algo
                :key-id   ?key-id)
              cause)))

        x-key
        (or
          (when (map? x-key) ; mkc-entry
            (get x-key (case key-type :prv :key-prv, :pub :key-pub, :sym :key-sym, (Object.))))
          x-key)]

    (enc/cond
      (not (or (nil? ?key-id) (string? ?key-id)))
      (fail! (ex-info "Unexpected `ChainKey` :key-id type" {:expected '?string, :actual {:value ?key-id, :type (type ?key-id)}}))

      (chainkey? x-key)
      (enc/cond
        :let [key-type* (.-key-type ^ChainKey x-key)]
        (not= key-type* key-type)
        (fail! (ex-info "Unexpected `ChainKey` :key-type value" {:expected key-type, :actual key-type*}))

        :let [key-algo* (.-key-algo ^ChainKey x-key)]
        (and ?key-algo (not= key-algo* ?key-algo))
        (fail! (ex-info "Unexpected `ChainKey` :key-algo value" {:expected ?key-algo, :actual key-algo*}))

        :let [key-id* (.-?key-id ^ChainKey x-key)]
        (and ?key-id (not= key-id* ?key-id))
        (ChainKey. (have key-type*) (have key-algo*) (.-?meta ^ChainKey x-key) ?key-id (.-key-cnt ^ChainKey x-key))

        :else x-key)

      :else
      (case key-type
        :prv
        (try
          (let [key-prv  (impl/as-key-prv ?key-algo ?needs x-key)
                key-algo (impl/keypair-algo key-prv)]
            (ChainKey. :prv (have key-algo) nil ?key-id key-prv))
          (catch Throwable t (fail! t)))

        :pub
        (try
          (let [key-pub  (impl/as-key-pub ?key-algo ?needs x-key)
                key-algo (impl/keypair-algo key-pub)]
            (ChainKey. :pub (have key-algo) nil ?key-id key-pub))
          (catch Throwable t (fail! t)))

        :sym
        (enc/cond
          (contains? #{:random :random-128-bit :random-256-bit :random-512-bit} x-key)
          (let [ba-len
                (case x-key
                  ;; Specific sizes currently undocumented
                  :random         impl/default-sym-key-len
                  :random-128-bit (bytes/n-bits->n-bytes 128)
                  :random-256-bit (bytes/n-bits->n-bytes 256)
                  :random-512-bit (bytes/n-bits->n-bytes 512))]
            (ChainKey. :sym :symmetric nil ?key-id (impl/rand-ba ba-len)))

          (enc/bytes? x-key)
          (if (>= (alength ^bytes x-key) impl/default-sym-key-len)
            (ChainKey. :sym :symmetric nil ?key-id x-key)
            (fail!
              (ex-info
                (format "Symmetric keys must be at least %s bytes long" impl/default-sym-key-len)
                {:length {:expected impl/default-sym-key-len, :actual (alength ^bytes x-key)}})))

          :else (fail! (ex-info "Unexpected `ChainKey` :key-sym type" {:expected 'bytes, :actual (type x-key)})))
        (enc/unexpected-arg! key-type
          {:expected #{:prv :pub :sym}
           :context  `-chainkey})))))

(comment
  [(-chainkey :sym :symmetric nil nil (impl/rand-ba 32))
   (-chainkey :pub :rsa-1024  nil nil (impl/keypair-create :rsa-1024))
   (=
     (-chainkey :sym :symmetric nil nil (byte-array (range 32)))
     (-chainkey :sym :symmetric nil nil (byte-array (range 32))))])

;;;; KeyChain

(def ^:private reference-mkc
  "m-keychain, public data structure.
  Optimized for user ergonomics: readability, ease of update, etc."
  '{"a" {:key-algo :symmetric, :priority 10, :key-sym ck-a-sym-10}
    "b" {:key-algo :rsa-1024,  :priority 11, :key-prv ck-b-prv-rsa-11, :key-pub ck-b-pub-rsa-11}
    "c" {:key-algo :rsa-1024,  :priority 10, :key-prv ck-c-prv-rsa-10}
    "d" {:key-algo :dh-1024,   :priority 10, :key-prv ck-d-prv-dh-10}
    "e" {:key-algo :symmetric, :priority 11, :key-sym ck-e-sym-11}})

(def ^:private reference-midx
  "m-idex, private data structure.
  Optimized for fast + easy ckey lookup."
  '{:symmetric {:key-sym [ck-e-sym-11 ck-a-sym-10]}
    :rsa-1024  {:key-prv [ck-b-prv-rsa-11 ck-c-prv-rsa-10], :key-pub [ck-b-pub-rsa-11]}
    :dh-1024   {:key-prv [ck-d-prv-dh-10]}

    ;;; By capability
    :ka          {:key-prv [ck-d-prv-dh-10]}
    :sig         {:key-prv [ck-b-prv-rsa-11 ck-c-prv-rsa-10], :key-pub [ck-b-pub-rsa-11]}
    :asym-cipher {:key-prv [ck-b-prv-rsa-11 ck-c-prv-rsa-10], :key-pub [ck-b-pub-rsa-11]}
    :sym-cipher  {:key-sym [ck-e-sym-11 ck-a-sym-10]}})

(defn- mkc-next-key-id [m-keychain]
  (Integer/toString (inc (count m-keychain)) (min Character/MAX_RADIX 62)))

(defn- mkc-top-priority [m-keychain]
  (inc ^long
    (reduce-kv
      (fn [^long max-priority key-id {:keys [priority]}]
        (let [p (long (or priority -1))]
          (if (> p max-priority) p max-priority)))
      -1
      m-keychain)))

(comment
  (mkc-next-key-id  {"a" {}})
  (mkc-top-priority {"a" {}})
  (mkc-index reference-mkc))

(defprotocol IKeyChain
  (keychain-info    [kc]             "Returns {:keys [n-sym n-prv n-pub secret?]}")
  (keychain-freeze  [kc]             "Returns {:keys [ba-kc-prv ba-kc-pub ba-kc_]}")
  (keychain-ckeys   [kc index-path]  "Returns sorted ?[<ChainKey> ... <ChainKey>]")
  (keychain-update  [kc validate? f] "Returns (possibly new) `KeyChain`"))

(declare
  ^:private -keychain
  ^:private mkc-info
  ^:private mkc-index
  ^:private mkc-freeze
  ^:private mkc-thaw)

(deftype KeyChain [m-keychain m-info_ m-index_ m-frozen_ ?meta]
  clojure.lang.IDeref  (deref  [_]       m-keychain)
  clojure.lang.IHashEq (hasheq [_] (hash m-keychain))

  Object
  (toString [this] (str "KeyChain[" @m-info_ " " (enc/ident-hex-str this) "]"))
  (hashCode [this] (hash m-keychain))
  (equals   [this other] (and (instance? KeyChain other) (= m-keychain (.-m-keychain ^KeyChain other))))

  clojure.lang.IObj
  (meta     [_  ] ?meta)
  (withMeta [_ m] (KeyChain. m-keychain m-info_ m-index_ m-frozen_ m))

  IKeyChain
  (keychain-info    [_] @m-info_)
  (keychain-freeze  [_] @m-frozen_)
  (keychain-ckeys   [_ index-path] (not-empty (get-in @m-index_ index-path)))
  (keychain-update  [this validate? f]
    (let [new-mkc (f m-keychain)]
      (if (= new-mkc m-keychain)
        this
        (let [new-kc (-keychain ?meta new-mkc)]
          (when validate? @(.-m-frozen_ ^KeyChain new-kc)) ; Confirm freezable
          new-kc)))))

(enc/deftype-print-methods               KeyChain)
(defn  ^:public keychain? [x] (instance? KeyChain x))
(defn-         -keychain  [?meta m-keychain]
  (KeyChain.            m-keychain
    (delay (mkc-info    m-keychain))
    (delay (mkc-index   m-keychain))
    (delay (mkc-freeze  m-keychain))
    ?meta))

(defn keychain-restore
  "Thaws `KeyChain` from frozen byte[]s."
  ([ba-kc-prv ba-kc-pub] (-keychain nil (mkc-thaw ba-kc-prv ba-kc-pub)))
  ([ba-kc_             ] (-keychain nil (mkc-thaw ba-kc_))))

;;;; KeyChain public utils

(defn- auto-key-id! [v_ mkc] (vreset! v_ (mkc-next-key-id mkc)))

(defn ^:public keychain-add-symmetric-key
  "Produces a ?new `KeyChain` that contains the given symmetric key.

  `x-key` may be: `:random`, byte[] of length >= 32, or {:keys [key-sym]} map.
  New keys will by default get top priority, override with `:priority` option.

  Return value depends on `:return` option:
    `:keychain` - Returns (possibly new) `KeyChain` (default)
    `:map`      - Returns {:keys [keychain changed? key-id]}"

  [keychain x-key &
   [{:keys [key-id priority return]
     :or   {return :keychain}}]]

  (have? keychain? keychain)

  (let [auto-key-id_ (volatile! nil)
        kc1 keychain
        kc2
        (keychain-update kc1 false
          (fn [mkc]
            (let [key-id   (have string? (or key-id (auto-key-id! auto-key-id_ mkc)))
                  ckey     (-chainkey :sym :symmetric nil key-id x-key)
                  priority (or priority (mkc-top-priority mkc))]
              (assoc mkc key-id
                {:key-algo :symmetric, :priority priority, :key-sym ckey}))))]

    (case return
      :keychain kc2
      :map
      (enc/assoc-some
        {:keychain keychain, :changed? (not (identical? kc1 kc2))}
        :key-id @auto-key-id_)

      (enc/unexpected-arg! return
        {:expected #{:keychain :map}
         :context  `keychain-add-symmetric-key}))))

(comment (keychain-add-symmetric-key (keychain) :random {:return :map}))

(defn ^:public keychain-add-asymmetric-keypair
  "Produces a ?new `KeyChain` that contains the given asymmetric keypair.

  `x-keypair` may be: ∈ #{:rsa-<nbits> :dh-<nbits> :ec-<curve>},
  a `java.security.KeyPair`, or a map with {:keys [key-prv key-pub]}.

  New keys will by default get top priority, override with `:priority` option.

  Return value depends on `:return` option:
    `:keychain` - Returns (possibly new) `KeyChain` (default)
    `:map`      - Returns {:keys [keychain changed? key-id]}

    And see `*config*` for details:
      `keypair-creator`."

  {:arglists
   '([keychain x-keypair &
      [{:keys [key-id priority return]
        :or   {return :keychain}}]])}

  [keychain x-keypair & [opts]]
  (have? keychain? keychain)
  (let [{:keys [key-id priority return] :or {return :keychain}} opts
        {:keys [keypair-creator] :as opts+} (core/get-opts+ opts)

        keypair
        (have [:instance? java.security.KeyPair]
          (enc/cond
            (keyword? x-keypair) ; key-algo
            (let [kpc (force (have keypair-creator))]
              (kpc x-keypair))

            (map? x-keypair) ; mkc-entry
            (let [{:keys [key-algo key-prv key-pub]} x-keypair]
              (java.security.KeyPair.
                (if (chainkey? key-pub) (.-key-cnt ^ChainKey key-pub) (when key-pub (impl/as-key-pub key-algo nil key-pub)))
                (if (chainkey? key-prv) (.-key-cnt ^ChainKey key-prv) (when key-prv (impl/as-key-prv key-algo nil key-prv)))))
            x-keypair))

        {:keys [key-algo key-prv key-pub]} (impl/keypair-info keypair)

        auto-key-id_ (volatile! nil)
        kc1 keychain
        kc2
        (keychain-update keychain false
          (fn [mkc]
            (let [key-id   (have string? (or key-id (auto-key-id! auto-key-id_ mkc)))
                  priority (or priority (mkc-top-priority mkc))]
              (assoc mkc key-id
                (enc/assoc-some
                  {:key-algo key-algo, :priority priority}
                  :key-prv (when key-prv (-chainkey :prv key-algo nil key-id key-prv))
                  :key-pub (when key-pub (-chainkey :pub key-algo nil key-id key-pub)))))))]

    (case return
      :keychain kc2
      :map
      (enc/assoc-some
        {:keychain keychain, :changed? (not (identical? kc1 kc2))}
        :key-id @auto-key-id_)

      (enc/unexpected-arg! return
        {:expected #{:keychain :map}
         :context  `keychain-add-asymmetric-keypair}))))

(comment (keychain-add-asymmetric-keypair (keychain)
           (impl/keypair-create :rsa-1024)))

(defn ^:public keychain-update-priority
  "Returns a ?new `KeyChain` with the identified key's
  `:priority` updated to be (update-fn <old-priority>).

  Priority values can be any integer, positive or negative.
  When multiple keys in a `KeyChain` are appropriate for a
  task, the key with highest priority will be selected."

  [keychain key-id update-fn]

  (have? keychain? keychain)
  (have? string?   key-id)

  (keychain-update keychain false
    (fn [mkc]
      (if-let [mkc-entry (get mkc key-id)]
        (assoc mkc key-id
          (assoc mkc-entry :priority
            (update-fn (get mkc-entry :priority 0))))
        mkc))))

(defn ^:public keychain-normalize-priorities
  "Returns a ?new `KeyChain` with key priorities normalized
  to their relative rank order:
    {\"a\" {:priority -3}, \"b\" {:priority 8}} =>
    {\"a\" {:priority  0}, \"b\" {:priority 1}}"

  [keychain]
  (have? keychain? keychain)
  (keychain-update keychain false
    (fn [mkc]
      (let [m-norm-priorities  ; {<priority> <norm-priority>}, as ordinal ranks
            (let [m-priorities (into #{} (map #(get % :priority 0)) (vals mkc))]
              (into {} (map-indexed (fn [idx p] [p idx])) (sort m-priorities)))]

        (reduce-kv
          (fn [m key-id {:keys [priority] :as mkc-entry}]
            (if (empty? mkc-entry)
              m
              (assoc m key-id
                (assoc mkc-entry :priority (get m-norm-priorities priority)))))
          mkc
          mkc)))))

(comment
  (keychain-update-priority (keychain) "nx-id" inc)
  (->
    (keychain)
    (keychain-add-symmetric-key :random {:key-id "my-id"})
    (keychain-update-priority "my-id" (fn [p] -100))
    (keychain-update-priority "nx-id" dec)
    (keychain-normalize-priorities)
    (deref)))

(defn ^:public keychain-remove
  "Returns a ?new `KeyChain` with the identified key removed.
  Options:
    `:keep-private?` - Should only the public component of keypairs
                       be removed? (Default true)"
  [keychain key-id &
   [{:keys [keep-private?]
     :or   {keep-private? true}}]]

  (have? keychain? keychain)
  (have? string?   key-id)

  (keychain-update keychain false
    (fn [mkc]
      (if-let [mck (get mkc key-id)]
        (assoc mkc key-id ; Nb *always* keep entry for key-id
          (if (and keep-private? (get mck :key-prv))
            (dissoc mck :key-sym :key-pub)
            {}))
        mkc))))

(comment
  (->
    (keychain)
    (keychain-add-symmetric-key :random {:key-id "my-id"})
    (keychain-remove "my-id")))

(defn ^:public keychain
  "Returns a new `KeyChain` with key/pairs as specified by options:
    `:symmetric-keys`      - Seq of keys     given to `keychain-add-symmetric-key`
    `:asymmetric-keypairs` - Seq of keypairs given to `keychain-add-asymmetric-keypair`

  (keychain
    :symmetric-keys      [:random :random (byte-array [1 2 3 4))]
    :asymmetric-keypairs [:rsa-1024 :dh-1024 :ec-secp384r1])

  Options:
    `:empty?` - When truthy, returns a `KeyChain` without any keys
    `:only?`  - When truthy, returns a `KeyChain` with keys ONLY as
                specified in call options (ignores any keys specified in `*config*`)

    And see `*config*` for details:
      `symmetric-keys`, `asymmetric-keys`, `keypair-creator`."

  {:arglists '([& [{:keys [empty? only? symmetric-keys asymmetric-keys keypair-creator]}]])}
  [& [opts]]
  (let [{:keys [empty? only?]} opts]
    (if empty?
      (-keychain nil {})
      (let [{:keys [symmetric-keys asymmetric-keypairs keypair-creator] :as opts+}
            (if only? opts (core/get-opts+ opts))

            kc  (-keychain nil {})
            kc  (reduce (fn [acc in] (keychain-add-symmetric-key      acc in opts+)) kc symmetric-keys)
            kc  (reduce (fn [acc in] (keychain-add-asymmetric-keypair acc in opts+)) kc asymmetric-keypairs)]
        kc))))

(comment
  @(keychain)
  @(keychain {:empty? true})
  @(keychain
     {:symmetric-keys [(impl/rand-ba 32) :random]
      :asymmetric-keypairs
      [(impl/keypair-create :rsa-1024)
       (impl/keypair-create  :dh-1024)]}))

;;;; State utils

(defn- mkc-info
  "Returns {:keys [n-sym n-prv n-pub secret?]}."
  [m-keychain]
  (let [m
        (reduce-kv
          (fn [acc _key-id m-in]
            (let [acc (if (get m-in :key-sym) (update acc :n-sym #(inc (long (or % 0)))) acc)
                  acc (if (get m-in :key-prv) (update acc :n-prv #(inc (long (or % 0)))) acc)
                  acc (if (get m-in :key-pub) (update acc :n-pub #(inc (long (or % 0)))) acc)]
              acc))
          {}
          m-keychain)

        secret?
        (or
          (> (long (get m :n-sym 0)) 0)
          (> (long (get m :n-prv 0)) 0))]

    (assoc m :secret? secret?)))

(comment (mkc-info {"a" {:key-sym 'ckey} "b" {:key-prv 'ckey :key-pub 'ckey}}))

(defn- mkc-index
  "`reference-mkc` -> `reference-midx`, etc."
  [m-keychain]
  (let [sorted-ckeys ; [<ckey> ...]
        (fn self
          ([algo-pred]
           (enc/assoc-some {}
             :key-sym (self :key-sym algo-pred)
             :key-prv (self :key-prv algo-pred)
             :key-pub (self :key-pub algo-pred)))

          ([key-at algo-pred]
           (let [v-sorted-maps ; [{:keys [ckey sort-by]} ...]
                 (reduce-kv
                   (fn [v key-id m-ckey]
                     (if-let [ckey
                              (and
                                (algo-pred (get m-ckey :key-algo))
                                (do        (get m-ckey key-at)))]

                       (conj v {:ckey ckey, :sort-by [(get m-ckey :priority 0) key-id]})
                       (do     v)))
                   [] m-keychain)]

             ;; Desc sort: higher priority and alpha first ("2" > "0", etc.)
             (not-empty (mapv :ckey (sort-by :sort-by enc/rcompare v-sorted-maps))))))]

    (enc/assoc-some
      ;; By key-algo
      (let [key-algos (into #{} (map :key-algo) (vals m-keychain))] ; #{:symmetric :rsa-<nbits> :dh-<nbits> :ec-<curve> ...}
        (reduce (fn [m key-algo] (assoc m key-algo (sorted-ckeys #(= % key-algo))))
          {} key-algos))

      ;; By capability
      :ka          (sorted-ckeys (fn [key-algo] (impl/key-algo? key-algo [:asymmetric? :ka-algo])))
      :sig         (sorted-ckeys (fn [key-algo] (impl/key-algo? key-algo [:asymmetric? :sig-algo])))
      :asym-cipher (sorted-ckeys (fn [key-algo] (impl/key-algo? key-algo [:asymmetric? :asym-cipher-algo])))
      :sym-cipher  (sorted-ckeys (fn [key-algo] (impl/key-algo? key-algo [:symmetric?  :sym-cipher-algo]))))))

(comment (= (mkc-index reference-mkc) reference-midx))

(defn- mkc-freeze
  "Returns {:keys [ba-kc-prv ba-kc-pub ba-kc_]}."
  #_(df/reference-data-formats :keychain-<part>-v1)
  [m-keychain]
  (have? map? m-keychain)
  (let [fail! (fn [msg ex-data] (throw (ex-info msg ex-data)))
        entry-fn ; => ?{:keys [key-type key-algo priority key-ba]}
        (fn [key-id mkc-entry key-at expected-class key-ba-fn]

          (when-not (string? key-id)
            (fail! "Unexpected :key-id type in `KeyChain` entry"
              {:expected 'string, :actual {:value key-id, :type (type key-id)}}))

          (when-let [ckey (get mkc-entry key-at)]
            (let  [{:keys [key-algo priority]} mkc-entry
                   {:keys [key-type key-cnt], key-algo* :key-algo} @(have chainkey? ckey)]

              (enc/cond
                (not= key-algo* key-algo)
                (fail! "Unexpected :key-algo value in `KeyChain` entry"
                  {:expected key-algo, :actual key-algo*, :key-id key-id})

                (not (instance? expected-class key-cnt))
                (fail! "Unexpected key content type in `KeyChain` entry"
                  {:expected expected-class, :actual (type key-cnt), :key-id key-id})

                :else
                {:key-type (have key-type)
                 :key-algo (have key-algo)
                 :priority (have priority)
                 :key-ba   (key-ba-fn key-cnt)}))))

        freeze-part
        (fn [mode env-kid]
          (let [entry-fn ; => ?{:keys [key-type key-algo priority key-ba]}
                (case mode
                  :ba-kc-pub
                  (fn [key-id mkc-entry]
                    (entry-fn key-id mkc-entry :key-pub java.security.PublicKey
                      #(have (.getEncoded ^java.security.PrivateKey %))))

                  :ba-kc-prv
                  (fn [key-id mkc-entry]
                    (or
                      (entry-fn key-id mkc-entry :key-sym enc/bytes-class identity)
                      (entry-fn key-id mkc-entry :key-prv java.security.PrivateKey
                        #(have (.getEncoded ^java.security.PrivateKey %)))
                      {:key-type nil} ; Include all key-ids for `mkc-next-key-id`, etc.
                      ))

                  (enc/unexpected-arg! mode
                    {:expected #{:ba-kc-prv :ba-kc-pub}
                     :context  `mkc-freeze}))

                mkc
                (reduce-kv
                  (fn [m key-id mkc-entry]
                    (if-let [entry (entry-fn key-id mkc-entry)]
                      (assoc  m key-id entry)
                      (dissoc m key-id)))
                  m-keychain
                  m-keychain)]

            (bytes/with-out [out] [8192]
              (df/write-head      out)
              (df/write-kid       out :envelope env-kid)
              (df/write-flags     out nil nil)
              (df/write-resv      out)
              (bytes/write-ushort out (count mkc))
              (bytes/write-ushort out 0) ; Reserved for possible idx, etc.
              (enc/run-kv!
                (fn [key-id {:keys [key-type key-algo priority key-ba]}]
                  (bytes/write-dynamic-str  out key-id)
                  (df/write-kid             out :key-type key-type)
                  (when key-type
                    (df/write-kid           out :key-algo key-algo)
                    (bytes/write-ushort     out priority)
                    (bytes/write-dynamic-ba out key-ba)))
                mkc)
              (df/write-resv out))))

        ba-kc-prv (freeze-part :ba-kc-prv :keychain-prv-v1)
        ba-kc-pub (freeze-part :ba-kc-pub :keychain-pub-v1)]

    {:ba-kc-prv ba-kc-prv
     :ba-kc-pub ba-kc-pub
     :ba-kc_
     (delay
       (bytes/with-out [out] [16 ba-kc-prv ba-kc-pub]
         (bytes/write-dynamic-ba out ba-kc-prv)
         (bytes/write-dynamic-ba out ba-kc-pub)))}))

(comment
  (enc/map-vals count (keychain-freeze (keychain {:empty? true})))
  (let [{:keys [ba-kc-prv ba-kc-pub]}
        (mkc-freeze
          @(keychain {:symmetric-keys      [(impl/rand-ba 32)]
                      :asymmetric-keypairs [(impl/keypair-create :rsa-1024)]}))]
    [(count ba-kc-prv)
     (count ba-kc-pub)]))

(defn- mkc-thaw
  #_(df/reference-data-formats :keychain-<part>-v1)

  ([ba-kc_]
   (when-let [ba-kc (force ba-kc_)]
     (bytes/with-in [in] ba-kc
       (let [?ba-kc-prv (bytes/read-dynamic-?ba in)
             ?ba-kc-pub (bytes/read-dynamic-?ba in)]
         (mkc-thaw ?ba-kc-prv ?ba-kc-pub)))))

  ([ba-kc-prv ba-kc-pub]
   (have? [:or nil? enc/bytes?] ba-kc-prv ba-kc-pub)
   (let [thaw1
         (fn [acc env-kid ba]
           (bytes/with-in [in] ba
             (df/read-head!     in)
             (df/read-kid       in :envelope env-kid)
             (df/skip-flags     in)
             (df/read-resv      in)
             (let [n-entries (bytes/read-ushort in)
                   _resv     (bytes/read-ushort in)
                   acc
                   (enc/reduce-n
                     (fn [acc _]
                       (let [key-id   (bytes/read-dynamic-str in)
                             key-type (df/read-kid in :key-type)
                             mkc-entry
                             (when key-type
                               (let [key-algo (df/read-kid           in :key-algo)
                                     priority (bytes/read-ushort     in)
                                     key-ba   (bytes/read-dynamic-ba in) ; Was previously ?ba
                                     [key-at key-cnt]
                                     (case key-type
                                       :sym [:key-sym (do                           key-ba)]
                                       :prv [:key-prv (impl/as-key-prv key-algo nil key-ba)]
                                       :pub [:key-pub (impl/as-key-pub key-algo nil key-ba)]
                                       (enc/unexpected-arg! key-type
                                         {:expected #{:sym :prv :pub}
                                          :context  `mkc-thaw}))

                                     ckey (ChainKey. (have key-type) (have key-algo) nil key-id key-cnt)]
                                 {:key-algo key-algo, :priority priority, key-at ckey}))]

                         (update acc key-id
                           (fn [m] (conj (or m {}) mkc-entry)))))

                     acc n-entries)]

               (df/read-resv in)
               acc)))

         mkc {}
         mkc (if-let [ba ba-kc-prv] (thaw1 mkc :keychain-prv-v1 ba) mkc)
         mkc (if-let [ba ba-kc-pub] (thaw1 mkc :keychain-pub-v1 ba) mkc)]

     mkc)))

(comment
  (let [kc (keychain {:symmetric-keys      [(impl/rand-ba 32)]
                      :asymmetric-keypairs [(impl/keypair-create :rsa-1024)]})
        {:keys  [ba-kc-prv ba-kc-pub]} (mkc-freeze @kc)]
    (= (mkc-thaw ba-kc-prv ba-kc-pub) @kc)))

;;;;; Integration API
;; Utils used by core for KeyChain support

(defn- missing-ckey!
  ([      ex-data] (missing-ckey! nil ex-data))
  ([cause ex-data] (throw (ex-info "Appropriate key/s not available in `KeyChain`" ex-data cause))))

(defn get-ckeys-sym-cipher
  "Arity 1: for encryption =>  <ckey>
   Arity 2: for decryption => [<ckey> ...]."
  ([x-sym]
   (if (keychain? x-sym)
     (or
       (when-let [[ck1] (keychain-ckeys x-sym [:sym-cipher :key-sym])] ck1)
       (missing-ckey! {:need "Symmetric private key", :key-algo :sym, :key-type :sym}))
     (-chainkey :sym :symmetric nil nil x-sym)))

  ([x-sym ?key-id]
   (have? [:or nil? string? ?key-id])
   (if (keychain? x-sym)
     (if-let [key-id ?key-id]
       (let [mkc @x-sym]
         (or
           (when-let [ck (get-in mkc [key-id :key-sym])] [ck])
           (missing-ckey! {:need (str "Symmetric private key with id: " key-id),
                           :key-algo :sym, :key-id key-id, :key-type :sym})))
       (or
         (keychain-ckeys x-sym [:sym-cipher :key-sym])
         (missing-ckey! {:need "Symmetric private key",
                         :key-algo :symmetric, :key-type :sym})))

     [(-chainkey :sym :symmetric nil nil x-sym)])))

(comment :see-tests)

(defn get-ckeys-asym-cipher
  "Arity 1: for encryption =>  <ckey>
   Arity 3: for decryption => [<ckey> ...]."
  ([x-pub]
   (if (keychain? x-pub)
     (or
       (when-let [[ck1] (keychain-ckeys x-pub [:asym-cipher :key-pub])] ck1)
       (missing-ckey! {:need "Asymmetric public key with cipher support", :key-type :pub}))
     (-chainkey :pub nil [:asymmetric? :asym-cipher-algo] nil x-pub)))

  ([x-prv key-algo ?key-id]
   (have? [:or nil? string? ?key-id])
   (if (keychain? x-prv)
     (if-let [key-id ?key-id]
       (let [mkc @x-prv]
         (or
           (when-let [ck (get-in mkc [key-id :key-prv])] [ck])
           (missing-ckey! {:need (format "Asymmetric `%s` private key with cipher support and id: %s" key-algo key-id),
                           :key-algo key-algo, :key-id key-id, :key-type :prv})))
       (or
         (keychain-ckeys x-prv [key-algo :key-prv])
         (missing-ckey! {:need (format "Asymmetric `%s` private key with cipher support" key-algo),
                         :key-algo key-algo, :key-type :prv})))

     [(-chainkey :prv key-algo [:asymmetric? :asym-cipher-algo] nil x-prv)])))

(comment :see-tests)

(defn get-ckeys-sig
  "Arity 1: for signing      =>  <ckey>
   Arity 3: for verification => [<ckey> ...]."
  ([x-prv]
   (if (keychain? x-prv)
     (or
       (when-let [[ck1] (keychain-ckeys x-prv [:sig :key-prv])] ck1)
       (missing-ckey! {:need "Asymmetric private key with signature support", :key-type :prv}))
     (-chainkey :prv nil [:asymmetric? :sig-algo] nil x-prv)))

  ([x-pub key-algo ?key-id]
   (have? [:or nil? string? ?key-id])
   (if (keychain? x-pub)
     (if-let [key-id ?key-id]
       (let [mkc @x-pub]
         (or
           (when-let [ck (get-in mkc [key-id :key-pub])] [ck])
           (missing-ckey! {:need (format "Asymmetric `%s` public key with signature support and id: %s" key-algo key-id),
                           :key-algo key-algo, :key-id key-id, :key-type :pub})))
       (or
         (keychain-ckeys x-pub [key-algo :key-pub])
         (missing-ckey! {:need (format "Asymmetric `%s` public key with signature support" key-algo),
                         :key-algo key-algo, :key-type :pub})))

     [(-chainkey :pub key-algo [:asymmetric? :sig-algo] nil x-pub)])))

(comment :see-tests)

(defn- reduce-pairs
  "Reduces using (rf acc x y), with [x y] pairs as in (for [x xs, y ys] [x y])."
  [rf init xs ys]
  (reduce
    (fn [acc x]
      (reduce (enc/preserve-reduced (fn [acc y] (rf acc x y))) acc ys))
    init xs))

(comment (reduce-pairs (fn [acc x y] (conj acc x y)) [] [:a :b] [1 2]))

(defn- matching-ckey-pair? [ck-prv ck-pub]
  (let [{:keys [key-prv]} @ck-prv
        {:keys [key-pub]} @ck-pub]

    (when (and key-prv key-pub)
      (let [algo-prv (impl/keypair-algo key-prv)
            algo-pub (impl/keypair-algo key-pub)]
        (and algo-prv (= algo-prv algo-pub))))))

(defn- get-ckeys-ka*
  "Returns ?[<ckey> ...], may throw."
  [fail! prv? ?key-algo [x ?key-id]]
  (if (keychain? x)
    (if-let [key-id ?key-id]
      (let [key-algo (have ?key-algo)
            mkc @x]
        (or
          (when-let [ck (get-in mkc [key-id (if prv? :key-prv :key-pub)])] [ck])
          (missing-ckey! {:need (format "Asymmetric `%s` %s key with key id: %s" key-algo (if prv? "private" "public") key-id)
                          :key-algo ?key-algo, :key-id key-id, :key-type (if prv? :prv :pub)})))

      (keychain-ckeys x [(or ?key-algo :ka) (if prv? :key-prv :key-pub)]))
    [(-chainkey (if prv? :prv :pub) ?key-algo [:asymmetric? :ka-algo] nil x)]))

(defn get-ckeys-ka
  "Arity 2: for encryption =>  [<receiver-ckey-pub> <sender-ckey-prv>]
   Arity 3: for decryption => [[<receiver-ckey-prv> <sender-ckey-pub>] ...]."
  ([receiver-x-pub sender-x-prv]
   (let [fail! (fn [cause] (missing-ckey! cause
                             {:context :encrypt-with-2-keypairs,
                              :given {:receiver-pub (type receiver-x-pub)
                                      :sender-prv   (type sender-x-prv)}}))

         recvr-cks-pub (get-ckeys-ka* fail! false nil [receiver-x-pub nil])
         sendr-cks-prv (get-ckeys-ka* fail! true  nil [sender-x-prv   nil])]

     (or
       (reduce-pairs ; => [<pub> <prv>]
         (fn [_ recvr-ck-pub sendr-ck-prv]
           (when (matching-ckey-pair? sendr-ck-prv recvr-ck-pub)
             (reduced                [recvr-ck-pub sendr-ck-prv])))
         nil recvr-cks-pub sendr-cks-prv)

       (throw
         (ex-info "No matching asymmetric key pairs available for key agreement via given args"
           {:given-types
            {:receiver-key-pub (type receiver-x-pub)
             :sender-key-prv   (type sender-x-prv)}

            :key-algos
            {:receiver-key-pub (into #{} (mapv #(impl/keypair-algo (get @% :key-pub)) recvr-cks-pub))
             :sender-key-prv   (into #{} (mapv #(impl/keypair-algo (get @% :key-prv)) sendr-cks-prv))}})))))

  ([key-algo
    [receiver-x-prv ?receiver-key-id]
    [sender-x-pub   ?sender-key-id]]

   (let [fail! (fn [cause] (missing-ckey! cause
                             {:context :decrypt-with-2-keypairs,
                              :given {:receiver-prv (type receiver-x-prv)
                                      :sender-pub   (type sender-x-pub)}}))

         recvr-cks-prv (get-ckeys-ka* fail! true  key-algo [receiver-x-prv ?receiver-key-id])
         sendr-cks-pub (get-ckeys-ka* fail! false key-algo [sender-x-pub   ?sender-key-id])]

     (or
       (not-empty
         (reduce-pairs ; => [<prv> <pub>]
           (fn [acc recvr-ck-prv sendr-ck-pub]
             (if (matching-ckey-pair? recvr-ck-prv sendr-ck-pub)
               (conj acc             [recvr-ck-prv sendr-ck-pub])
               (do   acc)))
           [] recvr-cks-prv sendr-cks-pub))

       (throw
         (ex-info
           (format "No matching asymmetric `%s` key pairs available for key agreement via given args" key-algo)
           {:given-types
            {:receiver-key-prv (type receiver-x-prv)
             :sender-key-pub   (type sender-x-pub)}

            :key-algos
            {:requested        key-algo
             :receiver-key-prv (into #{} (mapv #(impl/keypair-algo (get @% :key-prv)) recvr-cks-prv))
             :sender-key-pub   (into #{} (mapv #(impl/keypair-algo (get @% :key-pub)) sendr-cks-pub))}}))))))

(comment :see-tests)

;;;; KeyChain encryption

(def ^:private ^:const error-msg-need-pwd-or-key-sym  "Must provide `:password` or `:key-sym` in opts")
(def ^:private ^:const error-msg-need-pwd-xor-key-sym "Must not provide both `:password` and `:key-sym` in opts")

(defn ^:public keychain-encrypt
  "Given a `KeyChain` and password or symmetric key,  returns a byte[]
  that includes:

    - Encrypted:
      - The entire keychain
      - Optional other content (see `ba-content` option below)

    - Unencrypted:
      - Any public keys in keychain (retrieve with `public-data`)
      - Optional AAD (see `aad-help`)
      - Envelope data necessary for decryption (specifies algorithms, etc.)

  Output can be safely stored (e.g. in a database).
  Decrypt output with: `keychain-decrypt`.

  See Tempel Wiki for detailed usage info, common patterns, examples, etc.

  Options:
    `:password`   - String, byte[], or char[]             as with `encrypt-with-password`
    `:key-sym`    - `KeyChain` (see `keychain`) or byte[] as with `encrypt-with-symmetric-key`

    `:ba-aad`     - See `aad-help`
    `:ba-akm`     - See `akm-help`
    `:ba-content` - Optional additional byte[] content that should be encrypted
                    and included in output for retrieval with `keychain-decrypt`.

    And see `*config*` for details:
      `hash-algo`, `sym-cipher-algo`, `pbkdf-algo`, `pbkdf-nwf`,
      `embed-key-ids?`, `embed-hmac?`, `backup-key`, `backup-opts`."

  #_(df/reference-data-formats :encrypted-keychain-v1)
  {:arglists
   '([keychain &
      [{:keys
        [password key-sym ba-content
         ba-aad ba-akm
         hash-algo sym-cipher-algo
         pbkdf-algo pbkdf-nwf
         embed-key-ids? embed-hmac?
         backup-key backup-opts]}]])}

  ^bytes
  [keychain & [opts]]
  (have? keychain? keychain)
  (let [{:keys [password key-sym ba-content]} opts
        {:as opts+
         :keys
         [#_password #_key-sym #_ba-content
          ba-aad ba-akm
          hash-algo sym-cipher-algo
          pbkdf-algo pbkdf-nwf
          embed-key-ids? embed-hmac?
          #_backup-key #_backup-opts]}
        (core/get-opts+ opts)

        _ (have? some? hash-algo sym-cipher-algo)
        _ (when (and password key-sym) (throw (ex-info error-msg-need-pwd-xor-key-sym {})))

        sck       (impl/as-symmetric-cipher-kit sym-cipher-algo)
        ba-iv     (impl/rand-ba impl/min-iv-len)
        ba-salt   (when password (impl/derive-ba-salt hash-algo ba-iv))
        pbkdf-nwf (if   password (pbkdf/pbkdf-nwf-parse pbkdf-algo pbkdf-nwf) 0)

        {:keys [ba-key1 ?ba-key-id]}
        (enc/cond
          password
          (let [ba-key0 (pbkdf/pbkdf pbkdf-algo impl/default-sym-key-len ba-salt password pbkdf-nwf)]
            {:ba-key1 (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm)})

          key-sym
          (let [ckey-sym (get-ckeys-sym-cipher key-sym)
                {:keys [key-sym key-id]} @ckey-sym
                ba-key0 (have enc/bytes? key-sym)]

            {:ba-key1    (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm)
             :?ba-key-id (when embed-key-ids? (bytes/?str->?utf8-ba key-id))})

          :else
          (throw (ex-info error-msg-need-pwd-or-key-sym {})))

        ?ba-ekey1b (get-backup-key-for-encryption ba-key1 opts+)
        {:keys [ba-kc-prv ba-kc-pub]} (keychain-freeze keychain)

        ba-cnt ; Private content
        (bytes/with-out [out] [16 ba-kc-prv ba-content]
          (bytes/write-dynamic-ba out ba-kc-prv)
          (bytes/write-dynamic-ba out ba-content)
          (df/write-resv          out))

        ba-ecnt
        (let [ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
          (impl/sck-encrypt sck ba-iv ba-key2 ba-cnt ba-aad))

        ehmac-size (if embed-hmac? (impl/hmac-len hash-algo) 0)

        ba-ekc ; ba-encrypted-keychain
        (bytes/with-out [out baos]
          [72 ba-aad ba-kc-pub ?ba-key-id ?ba-ekey1b ba-iv ba-ecnt ehmac-size]

          (df/write-head          out)
          (df/write-kid           out :envelope :encrypted-keychain-v1)
          (df/write-flags         out nil nil)
          (bytes/write-dynamic-ba out ba-aad)
          (bytes/write-dynamic-ba out ba-kc-pub)
          (bytes/write-dynamic-ba out ?ba-key-id)
          (df/write-resv          out)

          (df/write-kid           out :hash-algo       hash-algo)
          (df/write-kid           out :sym-cipher-algo sym-cipher-algo)
          (df/write-kid           out :pbkdf-algo      pbkdf-algo)
          (bytes/write-ushort     out pbkdf-nwf)
          (bytes/write-dynamic-ba out nil #_ba-salt)
          (df/write-resv          out)

          (bytes/write-dynamic-ba out ba-iv)
          (bytes/write-dynamic-ba out ba-ecnt)
          (bytes/write-dynamic-ba out ?ba-ekey1b)
          (df/write-resv          out)
          (impl/write-ehmac       out baos embed-hmac? hash-algo ba-key1 ba-iv)
          (df/write-resv          out))]

    ba-ekc))

(comment
  ;; [3696 127 166] bytes
  [(let [kc (keychain)               ]                            (count (keychain-encrypt kc {:password "pwd"})))
   (let [kc (keychain {:empty? true})]                            (count (keychain-encrypt kc {:password "pwd"})))
   (let [kc (keychain {:only?  true, :symmetric-keys [:random]})] (count (keychain-encrypt kc {:password "pwd"})))])

(declare try-decrypt-with-keys!)

(defn ^:public keychain-decrypt
  "Complement of `keychain-encrypt`.

  Given a `ba-encrypted-keychain` byte[] as returned by `keychain-encrypt`,
  and a password or symmetric key - checks if given password is correct.

  If incorrect, returns nil.
  If   correct, return value depends on `:return` option:
    `:keychain`   - Returns decrypted `KeyChain` (default)
    `:ba-content` - Returns decrypted byte[] content
    `:ba-aad`     - Returns verified unencrypted embedded ?byte[] AAD
    `:map`        - Returns {:keys [keychain ba-aad ba-content]} map

  See `keychain-encrypt` for details.
  See Tempel Wiki for detailed usage info, common patterns, examples, etc."

  #_(df/reference-data-formats :encrypted-keychain-v1)
  {:arglists
   '([ba-encrypted-keychain &
      [{:keys [password key-sym return ba-akm backup-key backup-opts ignore-hmac?]
        :or   {return :keychain}}]])}

  [ba-encrypted-keychain & [opts]]
  (let [ba-ekc (have enc/bytes? ba-encrypted-keychain)
        {:keys [password key-sym return] :or {return :keychain}} opts
        {:keys [ba-akm backup-key backup-opts ignore-hmac?] :as opts+}
        (core/get-opts+ opts)]

    (when (and password key-sym)
      (throw (ex-info error-msg-need-pwd-xor-key-sym {})))

    (bytes/with-in [in bais] ba-ekc
      (let [env-kid         :encrypted-keychain-v1
            _               (df/read-head!           in)
            _               (df/read-kid             in :envelope env-kid)
            _               (df/skip-flags           in)
            ?ba-aad         (bytes/read-dynamic-?ba  in)
            ?ba-kc-pub      (bytes/read-dynamic-?ba  in)
            ?key-id         (bytes/read-dynamic-?str in)
            _               (df/read-resv!           in)
            hash-algo       (df/read-kid             in :hash-algo)
            sym-cipher-algo (df/read-kid             in :sym-cipher-algo)
            ?pbkdf-algo     (df/read-kid             in :pbkdf-algo)
            pbkdf-nwf       (bytes/read-ushort       in)
            ?ba-salt        (bytes/read-dynamic-?ba  in)
            _               (df/read-resv!           in)
            ba-iv           (bytes/read-dynamic-ba   in)
            ba-ecnt         (bytes/read-dynamic-ba   in)
            ?ba-ekey1b      (bytes/read-dynamic-?ba  in)
            _               (df/read-resv!           in)
            ehmac*          (impl/read-ehmac*        in bais ba-ekc)
            _               (df/read-resv            in)

            hmac-pass!
            (fn [ba-key1]
              (if (or ignore-hmac? (impl/ehmac-pass? ehmac* ba-ekc hash-algo ba-key1 ba-iv))
                ba-key1
                (throw (ex-info impl/error-msg-bad-ehmac {}))))

            sck (impl/as-symmetric-cipher-kit sym-cipher-algo)
            ?ba-cnt
            (enc/cond
              :if-let [ba-key1 (get-backup-key-for-decryption ?ba-ekey1b opts+)]
              (try
                (let  [ba-key1 (hmac-pass!  ba-key1)
                       ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                  (impl/sck-decrypt sck ba-iv ba-key2 ba-ecnt ?ba-aad))
                (catch Throwable t
                  (throw (ex-info impl/error-msg-bad-backup-key {} t))))

              password
              (try
                (let [ba-salt (or ?ba-salt (impl/derive-ba-salt hash-algo ba-iv))
                      ba-key0 (pbkdf/pbkdf ?pbkdf-algo impl/default-sym-key-len ba-salt password pbkdf-nwf)
                      ba-key1 (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm)
                      ba-key1 (hmac-pass!  ba-key1)
                      ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                  (impl/sck-decrypt sck ba-iv ba-key2 ba-ecnt ?ba-aad))
                (catch Throwable t nil))

              key-sym
              (try
                (let [ckeys-sym (get-ckeys-sym-cipher key-sym ?key-id)]
                  (try-decrypt-with-keys! `decrypt-with-symmetric-key
                    (some? ?key-id) ckeys-sym
                    (fn [ckey-sym]
                      (let [{:keys [key-sym]} @ckey-sym
                            ba-key0 (have enc/bytes? key-sym)
                            ba-key1 (impl/derive-ba-key1 hash-algo ba-key0 ba-iv ba-akm)
                            ba-key1 (hmac-pass!  ba-key1)
                            ba-cnt
                            (let [ba-key2 (impl/derive-ba-key2 hash-algo ba-key1 ba-iv)]
                              (impl/sck-decrypt sck ba-iv ba-key2 ba-ecnt ?ba-aad))]
                        ba-cnt))))
                (catch Throwable t nil))

              :else
              (throw (ex-info error-msg-need-pwd-or-key-sym {})))]

        (when-let [ba-cnt ?ba-cnt]
          (bytes/with-in [in] ba-cnt
            (let [?ba-kc-prv (bytes/read-dynamic-?ba in)
                  ?ba-ucnt   (bytes/read-dynamic-?ba in) ; User content
                  _          (df/read-resv!          in)
                  keychain   (keychain-restore ?ba-kc-prv ?ba-kc-pub)]

              (case return
                :keychain   keychain
                :ba-content ?ba-ucnt
                :ba-aad     ?ba-aad
                :map
                (enc/assoc-some
                  {:keychain   keychain}
                  :ba-content  ?ba-ucnt
                  :ba-aad      ?ba-aad)

                :_test ; Undocumented, used for tests
                (enc/assoc-some
                  {:kc keychain}
                  :aad (bytes/?utf8-ba->?str ?ba-aad)
                  :cnt (bytes/?utf8-ba->?str ?ba-ucnt))

                (enc/unexpected-arg! return
                  {:expected #{:keychain :ba-content :ba-aad :map}
                   :context  `keychain-decrypt})))))))))

(comment
  (let [kc     (keychain)
        ba-key (impl/rand-ba 32)]
    (enc/qb 10 ; [2535.52 0.38]
      (keychain-decrypt (keychain-encrypt kc {:password "pwd"})  {:password "pwd"})
      (keychain-decrypt (keychain-encrypt kc {:key-sym  ba-key}) {:key-sym  ba-key}))))

;;;;

(defn try-keys
  "Returns {:keys [success error errors]}."
  [embedded-key-ids? possible-keys with-possible-key-fn]
  (let [nkeys (count possible-keys)]
    (if (== nkeys 1)
      (try
        (if-let [success (with-possible-key-fn (first possible-keys))]
          {:success success}
          {:error   (Exception. "Unexpected (falsey) `try-keys` result")})
        (catch Throwable t {:error t }))

      ;; >1 keys => using `KeyChain`/s with data written with {:embed-key-ids? false}
      (let [errors_ (volatile! [])]
        (assert (not embedded-key-ids?))
        (if-let [success
                 (reduce
                   (fn [_ possible-key]
                     (if-let [success
                              (try
                                (with-possible-key-fn possible-key)
                                (catch Throwable t (vswap! errors_ conj t) nil))]
                       (reduced success)
                       nil))
                   nil
                   possible-keys)]

          {:success success}
          {:errors  @errors_})))))

(comment (try-keys false {:a :k1 :b :k2} (fn [k] nil)))

(defn try-decrypt-with-keys!
  "Special case of `try-keys` that throws decryption errors on failure."
  [context embedded-key-ids? possible-keys decrypt-fn]
  (let [result (try-keys embedded-key-ids? possible-keys decrypt-fn)]
    (enc/cond
      :if-let [success (get result :success)] success
      :if-let [t       (get result :error)]
      (throw
        (ex-info
          (if embedded-key-ids?
            "Failed to decrypt Tempel data (1 identified key tried)"
            "Failed to decrypt Tempel data (1 unidentified key tried)")
          {:context context, :num-keys-tried 1, :embedded-key-ids? embedded-key-ids?}
          t))

      :else
      (let [errors (get result :errors)
            nkeys  (count possible-keys)]
        (throw
          (ex-info (str "Failed to decrypt Tempel data (" nkeys " unidentified keys tried)")
            {:context           context
             :num-keys-tried    nkeys
             :embedded-key-ids? embedded-key-ids?
             :errors            errors}))))))
