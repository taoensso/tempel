(ns ^:no-doc taoensso.tempel.pbkdf
  "Private ns, implementation detail.
  Key derivation stuff."
  (:refer-clojure :exclude [rand-nth])
  (:require
   [taoensso.encore       :as enc   :refer [have have?]]
   [taoensso.encore.bytes :as bytes :refer [as-ba]]
   [taoensso.tempel.impl  :as impl]))

(comment
  (remove-ns 'taoensso.tempel.pbkdf)
  (:api (enc/interns-overview)))

;; Other options incl.:
;;   - HKDF   Ref. <https://github.com/patrickfav/hkdf>,   etc. ; RFC 5869
;;   - Argon2 Ref. <https://github.com/phxql/argon2-jvm>,  etc.
;;   - BCrypt Ref. <https://github.com/patrickfav/bcrypt>, etc.

;;;;

(enc/compile-if com.lambdaworks.crypto.SCrypt
  (do
    (def ^:const have-dep-pbkdf-scrypt? true)
    (defn- pbkdf-scrypt
      "Password-Based Key Derivation Function as per RFC 7914.
      Key stretching: CPU and memory costs scale linearly with `n-work-factor`
      (which must be a power of 2).

      For info on scrypt params,
      Ref. <https://blog.filippo.io/the-scrypt-parameters/>"
      ^bytes
      [key-len ?ba-salt ba-secret n-work-factor
       {:keys [r    p]
        :or   {r 8, p 1}}]

      (let [ba-salt (or ?ba-salt (byte-array key-len))]
        (com.lambdaworks.crypto.SCrypt/scrypt ba-secret ba-salt
          n-work-factor r p key-len))))

  (do
    (def ^:const have-dep-pbkdf-scrypt? false)
    (defn- ^:missing-dependency pbkdf-scrypt
      "Missing dependency: `com.lambdaworks/scrypt`"
      ^bytes [key-len ba-salt ba-secret n-work-factor params]
      (impl/missing-dep!
        'com.lambdaworks.crypto.SCrypt
        'com.lambdaworks/scrypt
        pbkdf-scrypt))))

(comment (pbkdf-scrypt 32 (as-ba "salt") (as-ba "pwd") (Math/pow 2 14) {}))

(let [skf-pbkdf2-hmac-sha-256_
      (enc/thread-local
        (javax.crypto.SecretKeyFactory/getInstance
          "PBKDF2WithHmacSHA256"))]

  (defn- as-secret-key-factory-pbkdf2
    "Returns `javax.crypto.SecretKeyFactory`, or throws.
    Takes `algo-skf` ∈ #{:hmac-sha-256}."
    ^javax.crypto.SecretKeyFactory
    [algo-skf]
    (case algo-skf
      :hmac-sha-256 @skf-pbkdf2-hmac-sha-256_
      (enc/unexpected-arg! algo-skf
        {:expected #{:hmac-sha-256}
         :context  `as-secret-key-factory-pbkdf2}))))

(defn- pbkdf-pbkdf2
  "Password-Based Key Derivation Function as per
  PKCS #5 / RFC 8018 (formerly RFC 2898).

  Key stretching: CPU cost scales linearly with `n-iterations`.
  Takes `algo-skf` ∈ #{:hmac-sha-256}.

  Nb: doesn't automatically clear char[] password, consumer may want to
  clear manually for improved security."
  ^bytes
  [algo-skf key-len ?ba-salt ca-password n-iterations]

  ;; Ref. <https://xperti.io/blogs/java-aes-encryption-and-decryption/>
  (let [ba-salt (or ?ba-salt (byte-array key-len))
        skf (as-secret-key-factory-pbkdf2 algo-skf)
        pks
        (javax.crypto.spec.PBEKeySpec.
          ca-password
          ba-salt
          (int n-iterations)
          (bytes/n-bytes->n-bits key-len))

        ba-key (.getEncoded (.generateSecret skf pks))]

    (.clearPassword pks)
    ba-key))

(defn- ^:deprecated pbkdf-sha-512-deprecated
  "Custom Password-Based Key Deriviation Function.
  Key stretching: CPU cost scales linearly with `n-iterations`.

  Kept only for legacy reasons, prefer other standard PBKDF implementations."
  ^bytes
  [key-len ?ba-salt ba-secret n-iterations]

  (let [ba-salted-secret (bytes/ba-join ?ba-salt ba-secret) ; hmac would be better
        md (impl/as-message-digest :sha-512)]

    (as-ba key-len
      (enc/reduce-n (fn [^bytes acc in] (.digest md acc))
        ba-salted-secret n-iterations))))

;;;;

(defprotocol IPBKDFKit
  "Private protocol.
    - Ref nwfs generated with `pbkdf-nwf-estimate`.
    - Upgradability:
      - ref-nwfs (kw->nwf mappings) can be trivially upgraded over time.
      - nwf->rwf fn                 can not (would require new kit kid)."
  (^:private        pbkdf-kit-kid                  [_])
  (^:private        pbkdf-kit-ref-nwfs             [_])
  (^:private ^long  pbkdf-kit-nwf->rwf             [_ nwf])
  (^:private ^bytes pbkdf-kit-derive-ba-key ^bytes [_ key-len ?ba-salt password rwf]))

(deftype PBKDFKit-scrypt-r8p1-v1 []
  IPBKDFKit
  (pbkdf-kit-kid      [_] :scrypt-r8p1-v1) ; Version 1, r=8, p=1
  (pbkdf-kit-ref-nwfs [_] {:rmin 0, :r10 10, :r50 13, :r100 14, :r200 15, :r500 16, :r1000 17, :r2000 18, :r5000 19, :rmax 21})
  (pbkdf-kit-nwf->rwf [_ nwf] (long (Math/pow 2 (inc (long nwf)))))
  (pbkdf-kit-derive-ba-key [_ key-len ?ba-salt password rwf]
    (pbkdf-scrypt key-len ?ba-salt (as-ba password) rwf {:r 8, :p 1})))

(deftype PBKDFKit-pbkdf2-hmac-sha-256-v1 []
  IPBKDFKit
  (pbkdf-kit-kid      [_] :pbkdf2-hmac-sha-256-v1) ; Version 1
  (pbkdf-kit-ref-nwfs [_] {:rmin 0, :r10 6, :r50 28, :r100 55, :r200 111, :r500 277, :r1000 554, :r2000 1108, :r5000 2771, :rmax 11075})
  (pbkdf-kit-nwf->rwf [_ nwf] (* 1024 (long nwf)))
  (pbkdf-kit-derive-ba-key [_ key-len ?ba-salt password rwf]
    (pbkdf-pbkdf2 :hmac-sha-256 key-len ?ba-salt (bytes/as-ca password) rwf)))

(deftype PBKDFKit-sha-512-v1-deprecated []
  IPBKDFKit
  (pbkdf-kit-kid      [_] :sha-512-v1-deprecated) ; Version 1
  (pbkdf-kit-ref-nwfs [_] {:rmin 0, :r10 16, :r50 80, :r100 160, :r200 322, :r500 802, :r1000 1605, :r2000 3208, :r5000 8013, :rmax 31982})
  (pbkdf-kit-nwf->rwf [_ nwf] (* 1024 (long nwf)))
  (pbkdf-kit-derive-ba-key [_ key-len ?ba-salt password rwf]
    (pbkdf-sha-512-deprecated key-len ?ba-salt (as-ba password) rwf)))

(def pbkdf-kit-best-available
  (enc/cond
    have-dep-pbkdf-scrypt?                                            :scrypt-r8p1-v1
    (impl/non-throwing? (as-secret-key-factory-pbkdf2 :hmac-sha-256)) :pbkdf2-hmac-sha-256-v1
    (impl/non-throwing? (impl/as-message-digest :sha-512))            :sha-512-v1-deprecated
    (throw (ex-info "No viable PBKDF kit available" {}))))

(comment pbkdf-kit-best-available)

(let [kit-scrypt-r8p1-v1         (PBKDFKit-scrypt-r8p1-v1.)
      kit-pbkdf2-hmac-sha-256-v1 (PBKDFKit-pbkdf2-hmac-sha-256-v1.)
      kit-sha-512-v1-deprecated  (PBKDFKit-sha-512-v1-deprecated.)
      expected #{:scrypt-r8p1-v1 :pbkdf2-hmac-sha-256-v1 :sha-512-v1-deprecated}]

  (defn- as-pbkdf-kit
    "Returns `IPBKDFKit` implementer, or throws.
    Takes `kit` ∈ #{:scrypt-r8p1-v1 :pbkdf2-hmac-sha-256-v1 :sha-512-v1-deprecated}."
    [pbkdf-algo]
    (if (keyword? pbkdf-algo)
      (case       pbkdf-algo
        :best-available         (as-pbkdf-kit pbkdf-kit-best-available)
        :scrypt-r8p1-v1         kit-scrypt-r8p1-v1
        :pbkdf2-hmac-sha-256-v1 kit-pbkdf2-hmac-sha-256-v1
        :sha-512-v1-deprecated  kit-sha-512-v1-deprecated
        (enc/unexpected-arg! pbkdf-algo
          {:expected expected
           :context  `as-pbkdf-kit}))

      (enc/satisfies! IPBKDFKit pbkdf-algo
        {:expected expected
         :context  `as-pbkdf-kit}))))

(comment (as-pbkdf-kit pbkdf-kit-best-available))

;;;;

(defn pbkdf-nwf-estimate
  "Returns normalized work factor (nwf) estimate/s for which pbkdf runtime best
  matches given msecs target/s on the current system:

    (pbkdf-nwf-estimate :pbkdf2-hmac-sha-256-v1 [2 3] 200) =>
      Runs pbkdf2 a total of 2x3=6 times to estimate the normalized
      work factor that yields a ~200 msec runtime on the current system.

  Expensive!! Don't use in production.
  Used internally to help generate reference `nwf` consts:
    `:ref-10-msecs`, `:ref-100-msecs`, etc."

  ([pbkdf-algo bench-spec msecs-target-or-targets]
   (let [pbkdf-kit (as-pbkdf-kit pbkdf-algo)]

     (pbkdf-nwf-estimate bench-spec
       (fn kfn [rwf] (pbkdf-kit-derive-ba-key pbkdf-kit 32 (as-ba "salt") "pwd" rwf))
       (fn sfn [nwf] (pbkdf-kit-nwf->rwf      pbkdf-kit nwf))
       (get (pbkdf-kit-ref-nwfs pbkdf-kit) :r1000)
       msecs-target-or-targets)))

  ;; Low-level API
  ([bench-spec kfn sfn nwf-to-probe msecs-target-or-targets]
   ;; Assumes (kfn rwf) runtime increases linearly with rwf.
   ;; Scaling fn `sfn` need not be linear.

   (if (vector? msecs-target-or-targets) ; Bulk targets
     (mapv (fn [msecs] (pbkdf-nwf-estimate bench-spec kfn sfn nwf-to-probe msecs))
       msecs-target-or-targets)

     ;; Single target
     (let [[n-sets n-laps] (if (vector? bench-spec) bench-spec [4 bench-spec])

           msecs-target  (long msecs-target-or-targets)
           rwf           (long (sfn nwf-to-probe)) ; Raw/scaled work factor

           msecs-per-set (double (enc/qb bench-spec (kfn rwf)))
           msecs-per-lap (double (/ msecs-per-set (double n-laps)))
           msecs-per-rwf (double (/ msecs-per-lap (double rwf)))

           ;; This works only for linear sfn (so not for scrypt, etc.)
           ;; msecs-per-nwf (double (/ msecs-per-lap (double nwf-to-probe)))
           ;; nwf-proposed  (long (/ (double msecs-target) msecs-per-nwf))

           nwf-proposed
           ;; Search for wf for which (sfn wf) best predicts msecs-target
           (loop [nwf-prop 0]
             (let [nwf-next (inc nwf-prop)
                   msecs-predicted      (* (long (sfn nwf-prop)) msecs-per-rwf)
                   msecs-predicted-next (* (long (sfn nwf-next)) msecs-per-rwf)]

               (if (and
                     (< msecs-predicted      msecs-target)
                     (< msecs-predicted-next msecs-target))
                 (recur nwf-next)

                 (let [delta      (Math/abs (- msecs-predicted      msecs-target))
                       delta-next (Math/abs (- msecs-predicted-next msecs-target))]

                   (if (< delta delta-next) nwf-prop nwf-next)))))

           msecs-actual (enc/time-ms (kfn (sfn nwf-proposed)))
           msecs-delta  (- msecs-actual (long msecs-target))
           error-perc   (enc/perc msecs-delta msecs-actual)
           estimate
           {:nwf            nwf-proposed
            :actual-msecs   msecs-actual
            :error {:msecs  msecs-delta
                    :perc   error-perc
                    :status (if (<= error-perc 10) :okay :warn)}}]

       (if (> ^long nwf-proposed bytes/range-ushort)
         (throw
           ;; If target msecs is reasonable, => scaling fn may need adjustment (breaking!)
           (ex-info "Estimated PBKDF normalized work factor exceeds unsigned byte range"
             estimate))

         estimate)))))

(comment ; Reference normalized work factors
  (let [msecs-targets [10 50 100 200 500 1000 2000 5000 20000]]
    [(pbkdf-nwf-estimate :scrypt-r8p1-v1         [2 2] msecs-targets)
     (pbkdf-nwf-estimate :sha-512-v1-deprecated  [2 2] msecs-targets)
     (pbkdf-nwf-estimate :pbkdf2-hmac-sha-256-v1 [2 2] msecs-targets)])

  ;; Times from 2020 8-core MBP M1 2020 w/ 16GB memory
  {:scrypt-r8p1-v1
   [{:nwf 10, :actual-msecs 7,     :error {:msecs    -3, :perc -43, :status :warn}}
    {:nwf 13, :actual-msecs 58,    :error {:msecs     8, :perc  14, :status :warn}}
    {:nwf 14, :actual-msecs 117,   :error {:msecs    17, :perc  15, :status :warn}}
    {:nwf 15, :actual-msecs 238,   :error {:msecs    38, :perc  16, :status :warn}}
    {:nwf 16, :actual-msecs 518,   :error {:msecs    18, :perc   3, :status :okay}}
    {:nwf 17, :actual-msecs 1053,  :error {:msecs    53, :perc   5, :status :okay}}
    {:nwf 18, :actual-msecs 1954,  :error {:msecs   -46, :perc  -2, :status :okay}}
    {:nwf 19, :actual-msecs 4400,  :error {:msecs  -600, :perc -14, :status :warn}}
    {:nwf 21, :actual-msecs 18620, :error {:msecs -1380, :perc  -7, :status :good}}]

   :sha-512-v1-deprecated
   [{:nwf 16,    :actual-msecs 10,    :error {:msecs  0, :perc  0, :status :good}}
    {:nwf 80,    :actual-msecs 49,    :error {:msecs -1, :perc -2, :status :good}}
    {:nwf 160,   :actual-msecs 98,    :error {:msecs -2, :perc -2, :status :good}}
    {:nwf 322,   :actual-msecs 201,   :error {:msecs  1, :perc  0, :status :good}}
    {:nwf 802,   :actual-msecs 500,   :error {:msecs  0, :perc  0, :status :good}}
    {:nwf 1605,  :actual-msecs 1001,  :error {:msecs  1, :perc  0, :status :good}}
    {:nwf 3208,  :actual-msecs 2003,  :error {:msecs  3, :perc  0, :status :good}}
    {:nwf 8013,  :actual-msecs 5002,  :error {:msecs  2, :perc  0, :status :good}}
    {:nwf 31982, :actual-msecs 20004, :error {:msecs  4, :perc  0, :status :good}}]

   :pbkdf2-hmac-sha-256-v1
   [{:nwf 6,     :actual-msecs 11,    :error {:msecs  1, :perc 9, :status :good}}
    {:nwf 28,    :actual-msecs 51,    :error {:msecs  1, :perc 2, :status :good}}
    {:nwf 55,    :actual-msecs 100,   :error {:msecs  0, :perc 0, :status :good}}
    {:nwf 111,   :actual-msecs 202,   :error {:msecs  2, :perc 1, :status :good}}
    {:nwf 277,   :actual-msecs 501,   :error {:msecs  1, :perc 0, :status :good}}
    {:nwf 554,   :actual-msecs 1001,  :error {:msecs  1, :perc 0, :status :good}}
    {:nwf 1108,  :actual-msecs 2003,  :error {:msecs  3, :perc 0, :status :good}}
    {:nwf 2771,  :actual-msecs 5008,  :error {:msecs  8, :perc 0, :status :good}}
    {:nwf 11075, :actual-msecs 19999, :error {:msecs -1, :perc 0, :status :good}}]})

(defn pbkdf-nwf-parse
  "Given a PBKDF normalized work factor `nwf`:
    - Ensures that `nwf` is ∈[rmin,rmax], throws when out of range.
    - Supports upgradeable kit-specific `nwf` keyword defaults.

  Returns ushort nwf, or throws."
  ^long [pbkdf-algo nwf]
  (let [pbkdf-kit (as-pbkdf-kit pbkdf-algo)
        ref-nwfs  (pbkdf-kit-ref-nwfs pbkdf-kit)
        {:keys [rmin rmax]} ref-nwfs

        rmax (min (long rmax) bytes/range-ushort)
        nwf
        (long
          (if (keyword? nwf)
            (case nwf
              (:ref-min        :rmin)  rmin
              (:ref-10-msecs   :r10)   (get ref-nwfs :r10)
              (:ref-50-msecs   :r50)   (get ref-nwfs :r50)
              (:ref-100-msecs  :r100)  (get ref-nwfs :r100)
              (:ref-200-msecs  :r200)  (get ref-nwfs :r200)
              (:ref-500-msecs  :r500)  (get ref-nwfs :r500)
              (:ref-1000-msecs :r1000) (get ref-nwfs :r1000)
              (:ref-2000-msecs :r2000) (get ref-nwfs :r2000)
              (:ref-5000-msecs :r5000) (get ref-nwfs :r10)
              (:ref-max        :rmax)  rmax
              (enc/unexpected-arg! nwf
                {:context `pbkdf-nwf-parse
                 :expected
                 #{:ref-10-msecs :ref-50-msecs :ref-100-msecs :ref-200-msecs
                   :ref-500-msecs :ref-1000-msecs :ref-2000-msecs :ref-5000-msecs}}))
            nwf))]

    (if (or (< nwf (long rmin)) (> nwf (long rmax)))
      (throw
        (ex-info (str "Invalid PBKDF normalized work factor: " nwf)
          {:pbkdf-kit (get pbkdf-kit :pbkdf-kit)
           :nwf {:given nwf :min rmin :max rmax}}))

      (bytes/as-ushort nwf))))

(defn pbkdf
  "Provides a ~consistent API over various Password Based Key Derivation
  Function (PBKDF) implementations.

  The underlying KDFs accessible here all include tunable \"key stretching\",
  making them appropriate for low-entropy secrets like passwords.

  Arguments:

    `pbkdf-algo`
       ∈ #{:scrypt-r8p1-v1 :pbkdf2-hmac-sha-256-v1 :sha-512-v1-deprecated}.

       Determines the underlying PBKDF implementation, and the
       possible values and effect of the `work-factor`.

    `key-len`
       The desired key length, in bytes.
       Often 16 or 32 bytes (=> 128 or 256 bit keys).

    `?ba-salt`
       An optional byte[] to be used as salt.
       Important for preventing rainbow/dictionary attacks, etc.

    `password`
       A password in the form of a string, byte[], or char[].
       Arrays may be preferable in some very high security environments
       since they can be manually cleared (mutated) immediately after use,
       leading to less time in memory.

    `normalized-work-factor`
      ℕ[0,65535] subset, range may be further restricted by given kit.

      Determines how expensive key derivation will be. The ideal value will
      depend on selected implementation (kit) and context (e.g. use case,
      system performance, frequency of key derivation, sensitivity of data
      being protected by resulting key, likelihood and nature of possible
      attacks, etc.).

      Some special reference values may be used:
        `:ref-10-msecs`   ; Takes ~10   msecs on reference system (2020 M1 MBP)
        `:ref-50-msecs`   ;       ~50   msecs
        `:ref-100-msecs`  ;       ~100  msecs
        `:ref-200-msecs`  ;       ~200  msecs
        `:ref-500-msecs`  ;       ~500  msecs
        `:ref-1000-msecs` ;       ~1000 msecs
        `:ref-2000-msecs` ;       ~2000 msecs
        `:ref-5000-msecs` ;       ~5000 msecs

      NB: the underlying work factors to which these keywords map will be
      updated over time to accomodate increases in computing (and so attack)
      power.

      See also `pbkdf-nwf-estimate` to estimate the nwf needed on your
      particular system to yield a specific target runtime."

  ^bytes [pbkdf-algo key-len ?ba-salt password normalized-work-factor]
  (let [pbkdf-kit (as-pbkdf-kit       pbkdf-algo)
        nwf       (pbkdf-nwf-parse    pbkdf-kit normalized-work-factor)
        rwf       (pbkdf-kit-nwf->rwf pbkdf-kit nwf)]

    (pbkdf-kit-derive-ba-key pbkdf-kit key-len
      ?ba-salt password rwf)))

(comment
  [(enc/time-ms (pbkdf :scrypt-r8p1-v1         16 nil "pwd" :r100))
   (enc/time-ms (pbkdf :pbkdf2-hmac-sha-256-v1 16 nil "pwd" :r100))
   (enc/time-ms (pbkdf :sha-512-v1-deprecated  16 nil "pwd" :r100))
   (enc/time-ms (pbkdf :best-available         16 nil "pwd" :r100))])
