(ns ^:no-doc taoensso.tempel.df
  "Private ns, implementation detail.
  Data format stuff."
  (:require
   [taoensso.encore       :as enc  :refer [have have?]]
   [taoensso.encore.bytes :as bytes])

  (:import
   [java.io
    DataOutput DataOutputStream
    DataInput  DataInputStream]))

(comment
  (remove-ns 'taoensso.tempel.df)
  (:api (enc/interns-overview)))

;;;; IDs
;; - `kid` => keyword id, used to uniquely identify some algo/kit/etc.
;; - `bid` => byte    id, used to uniquely freeze (serialize) some `kid`.
;;   - All standard `bid`s should be ∈ ℕ[0,126].
;;   - All `bid`s currently hard-coded, closed to extension.
;;   - `bid` 127           reserved for possible later use by >1 byte ids.
;;   - `bid`s ∈ ℤ[-128,-1] reserved for possible later use by users.
;;   - `bid`s included in envelope data during encryption so that decryption
;;     can automatically identify the correct config. This enables easy
;;     automatic migration of kit/algo/etc. over time.

(def ^:private ^:const error-msg-newer-version
  "The data might have been written by a newer version of Tempel, or it might be corrupt.")

(def ^:private ^:const error-msg-not-tempel
  "The data might not have been written by Tempel, or it might be corrupt.")

(let [m-ids
      (let [+entries
            (fn [acc kind m-kids-by-bid]
              (-> acc
                (assoc-in [:by-bid kind]                 m-kids-by-bid)
                (assoc-in [:by-kid kind] (enc/invert-map m-kids-by-bid))))]

        (-> {}
          (+entries :envelope
            {; 0 nil
             1 :encrypted-with-symmetric-key-v1
             2 :encrypted-with-password-v1
             3 :encrypted-with-1-keypair-hybrid-v1
             4 :encrypted-with-1-keypair-simple-v1
             5 :encrypted-with-2-keypairs-v1
             6 :encrypted-keychain-v1
             7 :keychain-prv-v1
             8 :keychain-pub-v1
             9 :signed-v1})

          (+entries :pbkdf-algo
            {0 nil
             1 :pbkdf2-hmac-sha-256-v1
             2 :scrypt-r8p1-v1
             3 :sha-512-v1-deprecated})

          (+entries :sym-cipher-algo
            {; 0 nil
             1 :aes-gcm-128-v1
             2 :aes-gcm-256-v1
             3 :aes-cbc-128-v1-deprecated
             4 :aes-cbc-256-v1-deprecated
             5 :chacha20-poly1305-v1})

          (+entries :asym-cipher-algo
            {; 0 nil
             1 :rsa-oaep-sha-256-mgf1})

          (+entries :sig-algo
            {; 0 nil
             1 :sha-256-rsa
             2 :sha-512-rsa
             3 :sha-256-ecdsa
             4 :sha-256-ecdsa})

          (+entries :ka-algo
            {; 0 nil
             1 :dh
             2 :ecdh})

          (+entries :key-algo
            {; 0  nil
             1  :symmetric
             2  :rsa-1024
             3  :rsa-2048
             4  :rsa-3072
             5  :rsa-4096
             6  :dh-1024
             7  :dh-2048
             8  :dh-3072
             9  :dh-4096
             10 :ec-secp256r1
             11 :ec-secp384r1
             12 :ec-secp521r1})

          (+entries :key-type
            {0 nil ; For removed ckey entries
             1 :sym
             2 :pub
             3 :prv})

          (+entries :hash-algo
            {; 0 nil
             1 :md5
             2 :sha-1
             3 :sha-256
             4 :sha-512})))

      lup
      (fn lookup-id [m kind id thaw?]
        (if-let [e (find m id)]
          (val e)
          (throw
            (ex-info
              (if thaw?
                (str "Unexpected Tempel identifier: `" id "`. " error-msg-newer-version)
                (str "Unexpected Tempel identifier: `" id "`"))
              {:identifier {:kind kind, :value id, :type (type id)}
               :expected   (set (keys m))}))))]

  (let [m (:by-kid m-ids)] (defn- freeze-kid [kind kid] (-> m (lup kind kind false) (lup kind kid false))))
  (let [m (:by-bid m-ids)] (defn- thaw-bid   [kind bid] (-> m (lup kind kind true)  (lup kind bid true)))))

(comment
  (thaw-bid :envelope (freeze-kid :envelope :encrypted-with-symmetric-key-v1))
  (thaw-bid :key-algo (freeze-kid :key-algo :symmetric)))

(defn write-kid [^DataOutput out kind kid] (.writeByte out (freeze-kid kind kid)))
(defn  read-kid
  ([^DataInput in kind             ] (thaw-bid kind (.readByte in)))
  ([^DataInput in kind expected-kid]
   (let [kid   (read-kid in kind)
         pass? (if (set?    expected-kid)
                 (contains? expected-kid kid)
                 (=         expected-kid kid))]
     (if pass?
       kid
       (throw
         (ex-info (str "Unexpected Tempel identifier: `" kid "`. " error-msg-newer-version)
           {:identifier {:actual kid, :expected expected-kid}
            :kind       kind}))))))

;;;; Headers, etc.

(let [ba-head (bytes/str->utf8-ba "TPL")]
  (defn write-head [^DataOutput out] (.write out ba-head))
  (defn  read-head [^DataInput   in]
    (try
      (let [ba (bytes/read-ba in 3)] ba)
      (catch java.io.EOFException _ nil)))

  (defn read-head? [^DataInput in] (when-let [ba (read-head in)] (enc/ba= ba ba-head)))
  (defn read-head! [^DataInput in]
    (let [ba (read-head in)]
      (or
        (and ba (enc/ba= ba ba-head))
        (throw
          (ex-info (str "Expected Tempel header not found in data stream. " error-msg-not-tempel)
            {:read {:actual (vec ba), :expected (vec ba-head)}}))))))

(defn write-resv       [^DataOutput out] (bytes/write-dynamic-ba out nil))
(defn  read-resv ^long [^DataInput   in] (long (.readByte in)))
(defn  read-resv!      [^DataInput   in]
  (let [b (read-resv in)]
    (or
      (== b (bytes/from-ubyte 0))
      (throw
        (ex-info
          (str "Reserved Tempel extension point unexpectedly in use. " error-msg-newer-version)
          {:value {:actual b, :expected 0}})))))

;;;; Flags
;; Efficient (BitSet) flag storage

(let [;; Can store 8 flags in 1 byte:
      ;;   - 5x Indexes 0->4 reserved for global flags (base schema)
      ;;   - 3x Indexes 5->7 reserved for local  flags (schema+)
      base-schema-freeze {:has-hmac 0 :has-backup-key 1}
      base-schema-thaw   (enc/invert-map base-schema-freeze)]

  (defn write-flags
    "m-flags: {:keys [has-hmac has-backup-key]} "
    [^DataOutput out schema+ m-flags]
    (let [flags    (reduce-kv (fn [acc k v] (if v (conj acc k) acc)) #{} m-flags)
          schema   (enc/fast-merge base-schema-freeze schema+)
          ba-flags (bytes/freeze-set schema flags)]
      (bytes/write-dynamic-ba out ba-flags)))

  (defn skip-flags [^DataInput in] (bytes/skip-dynamic-ba in))
  (defn read-flags [^DataInput in schema+]
    (when-let [ba (bytes/read-dynamic-?ba in)]
      (let [schema (enc/fast-merge base-schema-thaw schema+)]
        (try
          (bytes/thaw-set schema ba)
          (catch Throwable t
            (throw
              (ex-info (str "Unexpected Tempel flag encountered. " error-msg-newer-version)
                {} t))))))))

(comment (vec (bytes/freeze-set {0 0 1 1 2 2 3 3 4 4 5 5 6 6 7 7} #{0 1 2 3 4 5 6 7})))

;;;; Envelope data formats

(def reference-data-formats
  "{<envelope-id> [[<num-bytes> <purpose>] ...]}.
    - Public data includes: flags, aad, content, key-algo, key-ids
    - Other  data in order: other algos, params, content"

  '{:encrypted-with-password-v1
    [:public-data [3 head] [1 env] [$ ?ba-flags] [$ ?ba-aad]
     :main [1 hash-algo] [1 sym-cipher-algo] [1 pbkdf-algo] [2 pbkdf-nwf] [$ ba-salt] [$ ba-iv] [$ ba-ecnt] [$ ?ba-ekey1b]
     :end  [1 resv] [$ ?ba-ehmac] [1 resv]]

    :encrypted-with-symmetric-key-v1
    [:public-data [3 head] [1 env] [$ ?ba-flags] [$ ?ba-aad] [$ ?key-id]
     :main [1 hash-algo] [1 sym-cipher-algo] [$ ba-iv] [$ ba-ecnt] [$ ?ba-ekey1b]
     :end  [1 resv] [$ ?ba-ehmac] [1 resv]]

    :encrypted-with-1-keypair-<type>-v1 ; <type> ∈ #{hybrid simple}
    [:public-data [3 head] [1 env] [$ ?ba-flags] [$ ?ba-aad] [1 key-algo] [$ ?key-id]
     :main [?1 hash-algo] ?[1 sym-cipher-algo] [1 asym-cipher-algo] ?[$ ba-iv] [$ ba-ecnt] ?[$ ba-ekey0] ?[$ ?ba-ekey1b]
     :end  [1 resv] ?[$ ?ba-ehmac] ?[1 resv]]

    :encrypted-with-2-keypairs-v1
    [:public-data [3 head] [1 env] [$ ?ba-flags] [$ ?ba-aad] [1 key-algo] [$ ?receiver-key-id] [$ ?sender-key-id]
     :main [1 hash-algo] [1 ka-algo] [1 sym-cipher-algo] [$ ba-iv] [$ ba-ecnt] [$ ?ba-ekey1b]
     :end  [1 resv] [$ ?ba-ehmac] [1 resv]]

    :signed-v1
    [:public-data [3 head] [1 env] [$ ?ba-flags] [$ ?ba-aad] [1 key-algo] [$ ?key-id] [$ba-cnt]
     :main [1 hash-algo] [1 sig-algo] [$ ba-sig]
     :end  [1 resv]]

    :encrypted-keychain-v1
    [:public-data [3 head] [1 env] [$ ?ba-flags] [$ ?ba-aad] [$ ba-kc-pub] [$ ?key-id] [1 resv]
     :main
     [1 hash-algo] [1 sym-cipher-algo] [1 pbkdf-algo] [2 pbkdf-nwf] [$ ba-salt] [1 resv]
     [$ ba-iv] [$ ba-ecnt] [1 resv] [$ ba-ekey] [$ ?ba-ekey1b]
     :end [1 resv] [$ ?ba-hmac] [1 resv]]

    :keychain-<part>-v1 ; <part> ∈ #{prv pub}
    [:public-data [3 head] [1 env] [$ ?ba-flags] [1 resv] [2 n-entries] [1 resv]
     :rest
     [[[$ key-id] [1 key-type] ?[[1 key-algo] [2 key-priority] [$ key-cnt]]] ...]
     [1 resv]]})
