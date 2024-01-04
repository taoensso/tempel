(ns taoensso.tempel-tests
  (:require
   [clojure.test          :as test  :refer [deftest testing is]]
   [taoensso.encore       :as enc   :refer [have have? throws?]]
   [taoensso.encore.bytes :as bytes :refer [as-ba ba=]]
   [taoensso.tempel.df    :as df]
   [taoensso.tempel.impl  :as impl]
   [taoensso.tempel.pbkdf :as pbkdf]
   [taoensso.tempel.keys  :as keys]
   [taoensso.tempel       :as tempel])

  (:import [javax.crypto AEADBadTagException BadPaddingException]))

(comment
  (remove-ns      'taoensso.tempel-tests)
  (test/run-tests 'taoensso.tempel-tests))

;;;; Implementation

(deftest _headers
  [(is (=   (bytes/with-in [in] (bytes/with-out [out] 4 (df/write-head out) (.write out 1)) (df/read-head! in) (.readByte in)) 1))
   (is (->> (bytes/with-in [in] (bytes/with-out [out] 4 (.write out 1))  (df/read-head! in))
         (throws? :ex-info {:read {:expected [84 80 76]}})))])

(deftest _randomness
  (let [k1 (impl/with-srng-insecure-deterministic!!! 10 (:key-prv (impl/keypair-create* :rsa-2048)))
        k2 (impl/with-srng-insecure-deterministic!!! 10 (:key-prv (impl/keypair-create* :rsa-2048)))
        k3 (impl/with-srng-insecure-deterministic!!! 11 (:key-prv (impl/keypair-create* :rsa-2048)))]
    [(is    (= k1 k2))
     (is (not= k1 k3))]))

(deftest _hash-ba
  [(let [h (partial impl/hash-ba-concat :sha-256)
         ba-ref (h (as-ba 0))]
     (is (enc/revery? #(ba= ba-ref %) [(h) (h nil) (h nil nil) (h nil nil (as-ba 0))]) "Hashing of empty/nil byte[]s"))

   (is (= (vec (impl/hash-ba-concat  :md5 (as-ba "hello"))) [93 65 64 42 -68 75 42 118 -71 113 -99 -111 16 23 -59 -110]))
   (is (= (vec (impl/hash-ba-cascade :md5 (as-ba "hello"))) [98 16 -110 6 -120 13 56 -92 1 10 -104 -31 18 67 -110 74]))

   (is (= (vec (impl/hash-ba-concat  :sha-256 nil)) (vec (impl/hash-ba-concat  :sha-256 (byte-array 0)))))
   (is (= (vec (impl/hash-ba-cascade :sha-256 nil)) (vec (impl/hash-ba-cascade :sha-256 (byte-array 0)))))])

(deftest _hmac
  [(is (= (vec (impl/hmac :md5   (as-ba "secret") (as-ba "cnt"))) [23 67 122 6 109 -56 120 93 -90 43 -73 -68 5 -20 54 -62]))
   (is (= (vec (impl/hmac :sha-1 (as-ba "secret") (as-ba "cnt"))) [-40 11 -111 61 59 63 -44 72 -58 -47 49 16 103 -41 44 -95 -36 -84 -111 -86]))
   (is (=
         (vec (impl/hmac :sha-256 (as-ba "secret")     (as-ba "c1")     (as-ba "c2")))
         (vec (impl/hmac :sha-256 (as-ba "secret") nil (as-ba "c1") nil (as-ba "c2")))))

   (is (throws? (impl/hmac :sha-256 (byte-array 0)   (as-ba "c1"))))
   (is (throws? (impl/hmac :sha-256 (as-ba "secret") (byte-array 0))))
   (is (throws? (impl/hmac :sha-256 (as-ba "secret") (byte-array 0) (byte-array 0))))
   (is (enc/bytes?  (impl/hmac :sha-256 (as-ba "secret") (byte-array 0) (as-ba "c1"))))])

(deftest _pbkdf-pbkdf2
  (is (= (vec (#'pbkdf/pbkdf-pbkdf2 :hmac-sha-256 16 (as-ba "salt") (.toCharArray "pwd") 8000))
         [-29 115 -115 -87 92 119 -80 -118 76 -122 127 70 8 67 -43 114])))

(deftest _pbkdf-nwf-parse
  [(is (=  (pbkdf/pbkdf-nwf-parse :scrypt-r8p1-v1 :ref-100-msecs) 14))
   (is (=  (pbkdf/pbkdf-nwf-parse :scrypt-r8p1-v1 12)             12))
   (is (-> (pbkdf/pbkdf-nwf-parse :scrypt-r8p1-v1 (inc bytes/range-ushort)) throws?))])

(defn- mbytes ^long [n] (long (Math/floor (* (double n) 1024 1024))))

(let [pass? (fn [result] (if (coll? result) (every? boolean result) (boolean result)))]
  (defn- with-rand-data
    "Calls (f <rand-ba-content> <rand-?ba-aad>)."
    [max-len n-runs f]
    (and
      (pass? (f (byte-array 0)         nil))
      (pass? (f (impl/rand-ba max-len) (byte-array 0)))
      (pass? (f (byte-array 0)         (byte-array 0)))
      (reduce
        (fn [acc _]
          (let [ba-cnt                         (impl/rand-ba (impl/rand-long max-len))
                ?ba-aad (when (impl/rand-bool) (impl/rand-ba (impl/rand-long max-len)))]
            (if (pass? (f ba-cnt ?ba-aad))
              acc
              (reduced false))))
        true
        (range n-runs)))))

(comment (with-rand-data 32 64 (fn [ba-cnt ?ba-aad] [(is true) (is false) (is true)])))

(deftest _symmetric-cipher-kits
  (every? boolean
    (flatten
      (let [ba-key (as-ba 32 "pwd")
            ba-cnt (as-ba    "cnt")]

        (for [sym-cipher-algo
              [:aes-gcm-128-v1
               :aes-gcm-256-v1
               :aes-cbc-128-v1-deprecated
               :aes-cbc-256-v1-deprecated
               :chacha20-poly1305-v1]]

          (let [sck (impl/as-symmetric-cipher-kit sym-cipher-algo)
                can-aad? (impl/sck-can-aad? sck)]

            [(testing "Basic operation + ?AAD"
               [(let [ba-aad  (when can-aad? (impl/rand-ba 128))
                      ba-iv   (impl/rand-ba  (impl/sck-iv-len sck))
                      ba-ecnt (impl/sck-encrypt sck ba-iv ba-key ba-cnt ba-aad)]

                  [(is (->> (impl/sck-decrypt sck ba-iv ba-key            ba-ecnt ba-aad) enc/utf8-ba->str (= "cnt")))
                   (is (->> (impl/sck-decrypt sck ba-iv (as-ba 32 "!pwd") ba-ecnt ba-aad) (throws? #{AEADBadTagException BadPaddingException})) "Bad key")])

                (if-not can-aad?
                  :skip-aad-tests
                  (let [ba-cnt  (as-ba "cnt")
                        ba-iv   (impl/rand-ba (impl/sck-iv-len sck))
                        ba-ecnt (impl/sck-encrypt sck ba-iv ba-key ba-cnt nil)]

                    [(is (->> (impl/sck-decrypt sck ba-iv ba-key ba-ecnt nil) enc/utf8-ba->str (= "cnt")) "No AAD")
                     (is (->> (impl/sck-decrypt sck ba-iv ba-key ba-ecnt (impl/rand-ba 128))
                              (throws? AEADBadTagException)) "Bad AAD")]))

                (with-rand-data (mbytes 4) 256
                  (fn [ba-cnt ?ba-aad]
                    (let [?ba-aad (when can-aad? ?ba-aad)
                          ba-iv   (impl/rand-ba (impl/sck-iv-len sck))
                          ba-ecnt (impl/sck-encrypt sck ba-iv ba-key ba-cnt  ?ba-aad)
                          ba-dcnt (impl/sck-decrypt sck ba-iv ba-key ba-ecnt ?ba-aad)]
                      (is (bytes/ba= ba-cnt ba-dcnt)))))])

             (testing "Bad ba lengths"
               [(is
                  (->>
                    (impl/sck-encrypt sck (impl/rand-ba 4) (impl/rand-ba 128) (as-ba "cnt") nil)
                    (throws? :ex-info {:length {:target (impl/sck-iv-len sck), :actual 4}}))
                  "ba-iv too short")

                (is
                  (->>
                    (impl/sck-encrypt sck (impl/rand-ba 128) (impl/rand-ba 4) (as-ba "cnt") nil)
                    (throws? :ex-info {:length {:target (impl/sck-key-len sck), :actual 4}}))
                  "ba-key too short")])]))))))

(deftest _keypairs
  [(testing "Keypair equality"
     [(true?  (impl/key-algo= :rsa          :rsa-1024))
      (true?  (impl/key-algo= :rsa-1024     :rsa-1024))
      (false? (impl/key-algo= :rsa-2048     :rsa-1024))

      (true?  (impl/key-algo= :dh           :dh-1024))
      (true?  (impl/key-algo= :dh-1024      :dh-1024))
      (false? (impl/key-algo= :dh-2048      :dh-1024))

      (true?  (impl/key-algo= :ec           :ec-secp256r1))
      (true?  (impl/key-algo= :ec-secp256r1 :ec-secp256r1))
      (false? (impl/key-algo= :ec-secp384r1 :ec-secp256r1))

      (false? (impl/key-algo= :rsa-1024     :dh-1024))
      (false? (impl/key-algo= :rsa          :dh-1024))
      (false? (impl/key-algo= :rsa          :ec))])

   (testing "Keypair creation and verification"
     (let [{:keys [keypair, ba-pub key-pub, ba-prv key-prv]} (impl/keypair-create* :rsa-1024)]
       [(is (=   (impl/as-key-pub :rsa-1024 nil ba-pub)  key-pub))
        (is (=   (impl/as-key-prv :rsa-1024 nil ba-prv)  key-prv))
        (is (=   (impl/as-key-pub :rsa      nil ba-pub)  key-pub) "Loose algo")
        (is (=   (impl/as-key-pub :rsa      nil keypair) key-pub) "Loose algo")
        (is (=   (impl/as-key-prv :rsa      nil keypair) key-prv) "loose algo")
        (is (=   (impl/as-key-pub :rsa      nil keypair) key-pub) "Loose algo")
        (is (=   (impl/as-key-prv :rsa      nil keypair) key-prv) "Loose algo")
        (is (=   (impl/as-key-pub nil       nil keypair) key-pub)  "Auto algo")
        (is (=   (impl/as-key-pub nil       nil key-pub) key-pub)  "Auto algo")

        (is (->> (impl/as-key-pub :rsa-2048 nil ba-pub) (throws? :ex-info {:algo {:expected :rsa-2048, :actual :rsa-1024}})) "Mismatched key size")
        (is (->> (impl/as-key-pub :dh-1024  nil ba-pub) (throws? :ex-info {:error :decode-failure}))                         "Mismatched algo")]))

   (testing "Keypair needs"
     [(is (=   (impl/key-algo! :rsa-1024     [:asymmetric? :asym-cipher-algo]) :rsa-1024))
      (is (->> (impl/key-algo! :rsa-1024     [:asymmetric? :ka-algo])          (throws? :ex-info "need key agreement support")))
      (is (=   (impl/key-algo! :dh-1024      [:asymmetric? :ka-algo])          :dh-1024))
      (is (->> (impl/key-algo! :dh-1024      [:asymmetric? :sig-algo])         (throws? :ex-info "need signature support")))
      (is (->> (impl/key-algo! :symmetric    [:asymmetric?])                   (throws? :ex-info "need asymmetric type")))
      (is (=   (impl/key-algo! :ec-secp256r1 [])                               :ec-secp256r1))
      (is (->> (impl/key-algo! :ec-secp256r1 [:nonsense])                      (throws? :ex-info "doesn't meet need")))])

   (testing "Keypair info"
     [(is (= (set (keys (impl/keypair-info           (impl/keypair-create  :rsa-1024))))  #{:key-algo   :key-prv   :key-pub}))
      (is (= (set (keys (impl/keypair-info (:key-pub (impl/keypair-create* :rsa-1024))))) #{:key-algo #_:key-prv   :key-pub}))
      (is (= (set (keys (impl/keypair-info (:key-prv (impl/keypair-create* :rsa-1024))))) #{:key-algo   :key-prv #_:key-pub}))
      (is (=            (impl/keypair-info nil)   nil))
      (is (=            (impl/keypair-info "str") nil))])])

(deftest _asymmetric-cipher
  (let [asym-cipher-algo :rsa-oaep-sha-256-mgf1
        key-algo         :rsa-1024

        {:keys [ba-pub ba-prv]} (impl/keypair-create* key-algo)]

    [(let [ba-cnt (as-ba "cnt")
           ecnt   (impl/encrypt-asymmetric asym-cipher-algo key-algo ba-pub ba-cnt)]
       (is (= (enc/utf8-ba->str (impl/decrypt-asymmetric asym-cipher-algo key-algo ba-prv ecnt)) "cnt")))

     (with-rand-data 62 1024
       (fn [ba-cnt _?ba-aad]
         (let [ba-ecnt (impl/encrypt-asymmetric asym-cipher-algo key-algo ba-pub ba-cnt)
               ba-dcnt (impl/decrypt-asymmetric asym-cipher-algo key-algo ba-prv ba-ecnt)]
           (is (bytes/ba= ba-cnt ba-dcnt)))))]))

(deftest _key-shared-create
  (let [kp1 (impl/keypair-create :dh-1024)
        kp2 (impl/keypair-create :dh-1024)]

    (enc/ba=
      (impl/key-shared-create :dh :dh-1024 kp1 kp2)
      (impl/key-shared-create :dh :dh-1024 kp2 kp1))))

(deftest _signatures
  (let [key-algo :rsa-1024
        {ba-pub1 :ba-pub, ba-prv1 :ba-prv} (impl/keypair-create* key-algo)
        {ba-pub2 :ba-pub, ba-prv2 :ba-prv} (impl/keypair-create* key-algo)]

    [(let [ba-cnt1  (as-ba "cnt1")
           ba-cnt2  (as-ba "cnt2")
           ba-sig1  (impl/signature-create :sha-256-rsa key-algo ba-prv1 ba-cnt1)]
       [(is (true?  (impl/signature-verify :sha-256-rsa key-algo ba-pub1 ba-cnt1 ba-sig1)))
        (is (false? (impl/signature-verify :sha-256-rsa key-algo ba-pub1 ba-cnt2 ba-sig1)) "Mismatch: content")
        (is (false? (impl/signature-verify :sha-256-rsa key-algo ba-pub2 ba-cnt1 ba-sig1)) "Mismatch: keypair")])

     (with-rand-data (mbytes 4) 256
       (fn [ba-cnt _?ba-aad]
         (let [ba-sig (impl/signature-create :sha-256-rsa key-algo ba-prv1 ba-cnt)]
           (is (true? (impl/signature-verify :sha-256-rsa key-algo ba-pub1 ba-cnt ba-sig))))))]))

(deftest _embedded-hmacs
  (let [ba-iv   (impl/rand-ba 32)
        ba-key1 (impl/rand-ba 32)
        ba-key2 (impl/rand-ba 32)

        get-ba-data
        (fn [ba-cnt ba-key]
          (bytes/with-out [out baos] 1024
            (bytes/write-dynamic-ba out ba-cnt)
            (impl/write-ehmac out baos true :sha-256 ba-key ba-iv)))

        ba-data1 (get-ba-data (as-ba "cnt1") ba-key1)
        ba-data2 (get-ba-data (as-ba "cnt2") ba-key2)]

    (bytes/with-in [in bais] ba-data1
      (bytes/skip-dynamic-ba in)
      (let [ehmac* (impl/read-ehmac* in bais ba-data1)]
        [(is (true?  (impl/ehmac-pass? ehmac* ba-data1 :sha-256 ba-key1 ba-iv)))
         (is (false? (impl/ehmac-pass? ehmac* ba-data1 :sha-256 ba-key2 ba-iv)) "Bad key")
         (is (false? (impl/ehmac-pass? ehmac* ba-data2 :sha-256 ba-key2 ba-iv)) "Bad content")]))))

;;;; Key management

(def kci keys/keychain-info)
(def pd  @#'tempel/public-data-test)

(defn ckid  [x]  (get (enc/force-ref x) :key-id))
(defn ckids [xs] (mapv ckid xs))

(defn ckid-pair [[x y]] [(get (enc/force-ref x) :key-id), (get (enc/force-ref y) :key-id)])
(defn ckid-pairs [xys]  (mapv ckid-pair xys))

(deftest _keychains
  [(is (keys/keychain? (keys/keychain)))
   (is (= (kci (keys/keychain {:empty? true}))                                             {:secret? false}))
   (is (= (kci (keys/keychain {:symmetric-keys nil, :asymmetric-keypairs nil}))            {:secret? false}))
   (is (= (kci (keys/keychain {:only? true, :symmetric-keys [:random]}))                   {:secret? true, :n-sym 1}))
   (is (= (kci (keys/keychain {:only? true, :symmetric-keys [(impl/rand-ba 32) :random]})) {:secret? true, :n-sym 2}))
   (is (->>    (keys/keychain {:only? true, :symmetric-keys [(impl/rand-ba 5)  :random]})
         (throws? :ex-info {:length {:expected 32}})) "Symmetric key too short")

   (let [kc (keys/keychain {:only? true, :symmetric-keys [:random :random :random]})]
     (is (= (ckids (keys/keychain-ckeys kc [:symmetric :key-sym])) ["3" "2" "1"])
       "Key priority defaults to order of last-added"))

   (let [kc (->
              (keys/keychain {:empty? true})
              (keys/keychain-add-symmetric-key :random {:key-id "z"})
              (keys/keychain-add-symmetric-key :random {:key-id "a"})
              (keys/keychain-add-symmetric-key :random {:key-id "a"}) ; Replace
              (keys/keychain-add-symmetric-key :random {:key-id "y"})
              (keys/keychain-add-symmetric-key :random {:key-id "b"}))]
     (is (= (ckids (keys/keychain-ckeys kc [:symmetric :key-sym])) ["b" "y" "a" "z"])
       "Key priority defaults to order of last-added, regardless of key-id"))

   (let [kc (->
              (keys/keychain {:empty? true})
              (keys/keychain-add-symmetric-key :random {:key-id "z", :priority 3})
              (keys/keychain-add-symmetric-key :random {:key-id "a", :priority 100})
              (keys/keychain-add-symmetric-key :random {:key-id "a", :priority 1}) ; Replace
              (keys/keychain-add-symmetric-key :random {:key-id "y", :priority 2})
              (keys/keychain-add-symmetric-key :random {:key-id "b", :priority 0}))]
     (is (= (ckids (keys/keychain-ckeys kc [:symmetric :key-sym])) ["z" "y" "a" "b"])
       "Key priority can be customized"))

   (let [kc (->
              (keys/keychain {:empty? true})
              (keys/keychain-add-symmetric-key :random            {:key-id "first"})
              (keys/keychain-add-symmetric-key (as-ba (range 32)) {:key-id "first"}) ; Replace
              (keys/keychain-add-symmetric-key :random))]
     [(is (= (ckids (keys/keychain-ckeys kc [:symmetric :key-sym])) ["2" "first"]))
      (is (ba= (-> (get @kc "first") :key-sym deref :key-sym) (as-ba (range 32))))])

   (testing "Key priority by index path"
     (let [kc (keys/keychain {:symmetric-keys      [#_1 :random #_2 :random]
                              :asymmetric-keypairs [#_3 :rsa-1024 #_4 :rsa-2048 #_5 :ec-secp256r1 #_6 :dh-2048 #_7 :dh-2048]})]

       [(is (= (@#'keys/mkc-index @#'keys/reference-mkc) @#'keys/reference-midx))
        (is (= (kci kc) {:n-sym 2, :n-prv 5, :n-pub 5, :secret? true}))
        (is (= (ckids (keys/keychain-ckeys kc [:symmetric   :key-sym])) ["2" "1"]))
        (is (= (ckids (keys/keychain-ckeys kc [:asym-cipher :key-pub])) ["4" "3"]))
        (is (= (ckids (keys/keychain-ckeys kc [:ka          :key-prv])) ["7" "6" "5"]))
        (is (= (ckids (keys/keychain-ckeys kc [:sig         :key-prv])) ["5" "4" "3"]))
        (is (= (ckids (keys/keychain-ckeys kc [:dh-2048     :key-prv])) ["7" "6"]))
        (is (= (ckids (keys/keychain-ckeys kc [:dh-1024     :key-prv])) []))]))

   (testing "ChainKey extraction (based on key priority by index path)"
     (let [kc (keys/keychain {:symmetric-keys      [#_1 :random #_2 :random]
                              :asymmetric-keypairs [#_3 :rsa-1024 #_4 :rsa-2048 #_5 :ec-secp256r1 #_6 :dh-2048 #_7 :dh-2048]})]

       [(is (=   (ckid  (keys/get-ckeys-sym-cipher kc))      "2"))
        (is (=   (ckids (keys/get-ckeys-sym-cipher kc nil)) ["2" "1"]))
        (is (->>        (keys/get-ckeys-sym-cipher kc "nx") (throws? :ex-info {:key-id "nx"})))

        (is (= (ckid  (keys/get-ckeys-asym-cipher kc)) "4"))
        (is (= (ckids (keys/get-ckeys-asym-cipher kc :rsa-2048 nil)) ["4"]))
        (is (->>      (keys/get-ckeys-asym-cipher kc :rsa-2048 "nx") (throws? :ex-info {:key-id   "nx"})))
        (is (->>      (keys/get-ckeys-asym-cipher kc :rsa-3072 nil)  (throws? :ex-info {:key-algo :rsa-3072})))

        (is (= (ckid  (keys/get-ckeys-sig kc)) "5"))
        (is (= (ckids (keys/get-ckeys-sig kc :rsa-1024 nil)) ["3"]))
        (is (->>      (keys/get-ckeys-sig kc :rsa-1024 "nx") (throws? :ex-info {:key-id "nx"})))
        (is (->>      (keys/get-ckeys-sig kc :rsa-3072 nil)  (throws? :ex-info {:key-algo :rsa-3072})))

        (is (= (ckid-pair  (keys/get-ckeys-ka kc kc)) ["7" "7"]))
        (is (= (ckid-pairs (keys/get-ckeys-ka :dh-2048      [kc nil] [kc nil])) [["7" "7"] ["7" "6"] ["6" "7"] ["6" "6"]]))
        (is (= (ckid-pairs (keys/get-ckeys-ka :ec-secp256r1 [kc nil] [kc nil])) [["5" "5"]]))
        (is (->>           (keys/get-ckeys-ka :dh-2048      [kc nil] [kc "nx"]) (throws? :ex-info {:key-id "nx"})))
        (is (->>           (keys/get-ckeys-ka :ec-secp384r1 [kc nil] [kc nil])  (throws? :ex-info {:key-algos {:requested :ec-secp384r1}})))]))

   (let [kc1 (keys/keychain {:only? true, :symmetric-keys [#_1 :random #_2 :random #_3 :random #_4 :random]})
         kc2 (-> kc1
               (keys/keychain-update-priority   "2" #(- (long %) 100))
               (keys/keychain-remove            "4")
               (keys/keychain-remove            "4")
               (keys/keychain-remove            "nx")
               (keys/keychain-update-priority   "nx" inc))]

     [(is (= (ckids (keys/keychain-ckeys kc1 [:symmetric :key-sym])) ["4" "3" "2" "1"]))
      (is (= (ckids (keys/keychain-ckeys kc2 [:symmetric :key-sym])) ["3" "1" "2"]))
      (is (= (get @kc2 "4") {}) "Key removal keeps key-id entry")

      (is (= (enc/map-vals :priority @(do                                 kc2)) {"1" 0, "2" -99, "3" 2, "4" nil}))
      (is (= (enc/map-vals :priority @(keys/keychain-normalize-priorities kc2)) {"1" 1, "2"   0, "3" 2, "4" nil}))])

   (let [kc1 (keys/keychain {:symmetric-keys      [#_1 :random]
                             :asymmetric-keypairs [#_2 :rsa-1024 #_3 :dh-1024]})
         kc2 (keys/keychain
               {:symmetric-keys      [(get @kc1 "1")]
                :asymmetric-keypairs [(get @kc1 "2") (get @kc1 "3")]})

         kc3 (keys/keychain
               {:symmetric-keys      [(get @kc1 "1")]
                :asymmetric-keypairs [(get @kc1 "2") (dissoc (get @kc1 "3") :key-prv)]})]

     [(is (=  kc1 kc2) "KeyChain & ChainKey equality, can add/copy KeyChain entry maps")
      (is (= (kci kc1) {:n-sym 1, :n-prv 2, :n-pub 2, :secret? true}))
      (is (= (kci kc3) {:n-sym 1, :n-prv 1, :n-pub 2, :secret? true}))])

   (testing "Serialization and encryption"
     (let [kc (->
                (keys/keychain {:symmetric-keys      [#_1 :random]
                                :asymmetric-keypairs [#_2 :rsa-1024 #_3 :dh-1024 #_4 :ec-secp256r1]})
                (keys/keychain-add-symmetric-key      :random       {:key-id "a"})
                (keys/keychain-add-asymmetric-keypair :ec-secp384r1 {:key-id "b"})
                (keys/keychain-add-asymmetric-keypair :dh-2048      {:key-id "c", :priority 100})
                (keys/keychain-add-asymmetric-keypair :dh-2048      {:key-id "d"})
                (keys/keychain-remove "c"                           {:keep-private? true})
                (keys/keychain-remove "d"                           {:keep-private? false}))

           ba-key   (impl/rand-ba 32)
           ba-!key  (impl/rand-ba 32)

           key-sym  (keys/keychain {:only? true :symmetric-keys [:random]})
           !key-sym (keys/keychain {:only? true :symmetric-keys [:random]})]

       ;; More tests (incl. AAD, AKM, etc.) are in later section for core API

       (every? boolean
         (for [[key-opts !key-opts]
               [[{:password  "pwd"} {:password  "!pwd"}]
                [{:key-sym  ba-key} {:key-sym  ba-!key}]
                [{:key-sym key-sym} {:key-sym !key-sym}]]]

           (let [ba-enc (keys/keychain-encrypt kc     key-opts)
                 kc-dec (keys/keychain-decrypt ba-enc key-opts)]

             [(is (= (kci kc)     {:n-sym 2, :n-prv 5, :n-pub 4, :secret? true}))
              (is (= (kci kc-dec) {:n-sym 2, :n-prv 5, :n-pub 4, :secret? true}))
              (is (=  kc  kc-dec))

              (is (=            (get @kc-dec "d")   {}) "Keep key-ids for empty entries")
              (is (= (set (keys (get @kc-dec "c"))) #{:key-prv :key-algo :priority}))

              (is (= (keys/keychain-decrypt ba-enc !key-opts) nil)             "Bad key")
              (is (= (kci (:keychain (pd ba-enc))) {:n-pub 4, :secret? false}) "Public keychain in public data")

              (is (every? nil? (mapv #(or (:key-sym %) (:key-prv %)) (vals @(:keychain (pd ba-enc)))))
                "No private data in public keychain")])))))])

;;;; Core API

(do
  (def ba-cnt    (as-ba  "cnt"))
  (def ba-!cnt   (as-ba "!cnt"))
  (def ba-aad    (as-ba  "aad"))
  (def ba-!aad   (as-ba "!aad"))
  (def ba-akm    (as-ba  "akm"))
  (def ba-!akm   (as-ba "!akm"))
  (def master-kc (keys/keychain)))

(defmacro is= [form expect & [msg]]
  (if-let [expect-err (:err expect)]
    `(let [result-err# (try ~form nil (catch Throwable t# t#))]
       (is (boolean (enc/matching-error :any ~expect-err result-err#)) ~msg))

    (if (map? expect)
      `(is (enc/submap? ~form ~expect) ~msg)
      `(is (=           ~form ~expect) ~msg))))

(comment
  [(is= (/ 1 0)        {:err "Divide"})
   (is= {:a :A, :b :B} {:a :A})
   (is= true           true)
   (is= true           false)])

(defn- combinatorial-roundtrip-tests!
  "Runs roundtrip tests with a wide variety of input options
  and returns {:passed <num>}, or throws on first failure."
  [test-name input enc-fn dec-fn enc-key dec-key dec-!key]
  (let [t0       (System/currentTimeMillis)
        n-passed (enc/counter 0)
        failed_  (atom nil)
        sizes    [0 16 64 #_1024 #_4096 8192 #_16384]
        kind     (if (= input :rand-bytes) :ba :kc)]

    (println)
    (print (str "Starting combinatorial tests (" test-name "), this may take some time!"))
    (doall
      (for [input           (case kind :kc [input] :ba sizes)
            aad-size        sizes
            akm-size        sizes
            dec-key*        [:good :bad]
            ba-dec-akm*     [nil :good :bad]
            enc-backup-key  [nil master-kc]
            dec-backup-key  [nil master-kc]
            enc-backup-akm? [false true]
            dec-backup-akm* [:good :bad]
            embed-hmac?     [true false]
            :while          (not @failed_)]

        (let [_
              (let [n-passed @n-passed]
                (if (zero? ^long (mod n-passed 100))
                  (print (format "\n%5s:" n-passed))
                  (print "."))
                (flush))

              input      (case kind :kc input     :ba (impl/rand-ba input))
              ba-enc-aad (when (pos? ^long aad-size)  (impl/rand-ba aad-size))
              ba-enc-akm (when (pos? ^long akm-size)  (impl/rand-ba akm-size))
              ba-dec-akm (case ba-dec-akm* :good ba-enc-akm, :bad (impl/rand-ba 32) nil nil)
              dec-key    (case dec-key*    :good dec-key     :bad dec-!key)

              ba-enc-backup-akm (when enc-backup-akm? (impl/rand-ba (rand-int 128)))
              enc-backup-opts   (when enc-backup-akm? {:ba-akm                             ba-enc-backup-akm})
              dec-backup-opts   (when enc-backup-akm? {:ba-akm (case dec-backup-akm* :good ba-enc-backup-akm :bad (impl/rand-ba 32) nil nil)})
              enc-opts {:ba-akm ba-enc-akm :backup-key enc-backup-key :backup-opts enc-backup-opts :ba-aad ba-enc-aad :embed-hmac? embed-hmac?}
              dec-opts {:ba-akm ba-dec-akm :backup-key dec-backup-key :backup-opts dec-backup-opts :return :map}

              enc-result (try (enc-fn input      enc-key enc-opts) (catch Throwable t {:error t}))
              dec-result (try (dec-fn enc-result dec-key dec-opts) (catch Throwable t {:error t}))
              error
              (or
                (when-let [e (:error enc-result)]          [:enc-error e])
                (when-let [e (:error dec-result)]          [:dec-error e])
                (when (and (= kind :kc) (nil? enc-result)) [:dec-error :nil-result]))

              expect-success?
              (if (and enc-backup-key dec-backup-key)
                (and
                  (= enc-backup-key dec-backup-key)
                  (bytes/?ba=
                    (:ba-akm enc-backup-opts)
                    (:ba-akm dec-backup-opts))
                  :with-backup-key)

                (or
                  (and (= dec-key* :good) (bytes/?ba= ba-enc-akm ba-dec-akm) :with-primary-key)
                  false))

              success?
              (and
                (nil? error)
                (case kind
                  :ba
                  (and
                    (bytes/?ba= (:ba-content dec-result) input)
                    (bytes/?ba= (:ba-aad     dec-result) ba-enc-aad))

                  :kc
                  (and
                    (=          (:keychain dec-result) input)
                    (bytes/?ba= (:ba-aad   dec-result) ba-enc-aad))))]

          (if-let [pass? (is (= (boolean expect-success?) success?) (str "Combinatorial test (" test-name ")"))]
            (n-passed)
            (let [vec*     #(when-let [v (not-empty (vec (take 5 %)))] (conj v '...))
                  enc-opts (-> enc-opts (update :ba-aad vec*) (update :ba-akm vec*))
                  dec-opts (-> dec-opts (update :ba-aad vec*) (update :ba-akm vec*))]

              (reset! failed_
                {:success?   {:expected expect-success? :actual success?}
                 :opts       {:enc enc-opts :dec dec-opts}
                 :ba-content {:in (vec* ba-cnt)     :out (vec* (:ba-content dec-result))}
                 :ba-aad     {:in (vec* ba-enc-aad) :out (vec* (:ba-aad     dec-result))}
                 :error      error}))))))

    (let [msecs-elapsed (- (System/currentTimeMillis) t0)]
      (println)
      (println (str "Done! (Took " msecs-elapsed " msecs)"))
      (if-let [failed @failed_]
        (throw
          (ex-info (str "Combinatorial test (" test-name ") failed")
            {:msecs-elapsed msecs-elapsed :passed @n-passed :failed (dissoc failed :error)}
            (second (:error failed))))

        {:msecs-elapsed msecs-elapsed :passed @n-passed :passed? true}))))

(comment
  (let [kc1 (-> (keys/keychain) (keys/keychain-add-symmetric-key :random {:key-id "a"}))
        kc2 (-> (keys/keychain) (keys/keychain-add-symmetric-key :random {:key-id "a"}))]

    (combinatorial-roundtrip-tests! "roundtrip with symmetric key" :rand-bytes
      (fn enc-fn [ba-cnt key-sym opts] (tempel/encrypt-with-symmetric-key ba-cnt key-sym opts))
      (fn dec-fn [ba-enc key-sym opts] (tempel/decrypt-with-symmetric-key ba-enc key-sym opts))
      kc1 kc1 kc2))

  (let [kc (keys/keychain {:symmetric-keys      [:random :random]
                           :asymmetric-keypairs [:rsa-1024 :dh-1024 :ec-secp256r1]})

        ba-key  (impl/rand-ba 32)
        ba-!key (impl/rand-ba 32)]

    (combinatorial-roundtrip-tests! "keychain roundtrip"     kc
      (fn enc-fn [kc  key-opts opts] (keys/keychain-encrypt  kc (merge key-opts opts)))
      (fn dec-fn [ekc key-opts opts] (keys/keychain-decrypt ekc (merge key-opts opts)))
      {:key-sym  ba-key}
      {:key-sym  ba-key}
      {:key-sym  ba-!key})))

(deftest _core-roundtrips
  [(testing "Encryption with password"
     (let [enc (fn [ba-cnt pwd opts] (tempel/encrypt-with-password ba-cnt pwd (merge {}               opts)))
           dec (fn [ba-enc pwd opts] (tempel/decrypt-with-password ba-enc pwd (merge {:return :_test} opts)))]

       [(is= (dec (enc ba-cnt "pwd" {              })  "pwd" {               }) {:cnt "cnt"            } "-AKM, -AAD")
        (is= (dec (enc ba-cnt "pwd" {:ba-akm ba-akm})  "pwd" {:ba-akm ba-akm }) {:cnt "cnt"            } "+AKM, -AAD")
        (is= (dec (enc ba-cnt "pwd" {:ba-aad ba-aad})  "pwd" {               }) {:cnt "cnt", :aad "aad"} "-AKM, +AAD")
        (is= (dec (enc ba-cnt "pwd" {:ba-aad ba-aad
                                     :ba-akm ba-akm})  "pwd" {:ba-akm ba-akm }) {:cnt "cnt", :aad "aad"} "+AKM, +AAD")

        (is= (dec (enc ba-cnt "pwd" {              }) "!pwd" {               }) {:err "Unexpected HMAC" #_"Tag mismatch"} "Bad pwd")
        (is= (dec (enc ba-cnt "pwd" {:ba-akm ba-akm})  "pwd" {:ba-akm ba-!akm}) {:err "Unexpected HMAC" #_"Tag mismatch"} "Bad AKM")

        (is= (pd  (enc ba-cnt "pwd" {              })) {:kind :encrypted-with-password            } "Public data")
        (is= (pd  (enc ba-cnt "pwd" {:ba-aad ba-aad})) {:kind :encrypted-with-password, :aad "aad"} "Public data +AAD")

        (is= (dec (enc ba-cnt "pwd" {:backup-key master-kc               }) "pwd" {                     }) {:cnt "cnt"} "+Backup, use primary, -AKM, -AAD")
        (is= (dec (enc ba-cnt "pwd" {:backup-key master-kc :ba-akm ba-akm}) "pwd" {:ba-akm ba-akm       }) {:cnt "cnt"} "+Backup, use primary, +AKM, -AAD")
        (is= (dec (enc ba-cnt "pwd" {:backup-key master-kc               })  nil  {:backup-key master-kc}) {:cnt "cnt"} "+Backup, use backup,  -AKM, -AAD")
        (is= (dec (enc ba-cnt "pwd" {:backup-key master-kc :ba-akm ba-akm})  nil  {:backup-key master-kc}) {:cnt "cnt"} "+Backup, use backup,  +AKM, -AAD")

        (binding [tempel/*config* (merge tempel/*config* {:pbkdf-nwf :ref-10-msecs})]
          (is (:passed? (combinatorial-roundtrip-tests! "roundtrip with password" :rand-bytes enc dec "pwd" "pwd" "!pwd"))))]))

   (testing "Encryption with symmetric key"
     (let [enc (fn [ba-cnt key-sym opts] (tempel/encrypt-with-symmetric-key ba-cnt key-sym (merge {}               opts)))
           dec (fn [ba-enc key-sym opts] (tempel/decrypt-with-symmetric-key ba-enc key-sym (merge {:return :_test} opts)))
           kc1 (-> (keys/keychain) (keys/keychain-add-symmetric-key :random {:key-id "a"}))
           kc2 (-> (keys/keychain) (keys/keychain-add-symmetric-key :random {:key-id "a"}))]

       [(is= (dec (enc ba-cnt kc1 {              }) kc1 {               }) {:cnt "cnt"            } "-AKM, -AAD")
        (is= (dec (enc ba-cnt kc1 {:ba-akm ba-akm}) kc1 {:ba-akm ba-akm }) {:cnt "cnt"            } "+AKM, -AAD")
        (is= (dec (enc ba-cnt kc1 {:ba-aad ba-aad}) kc1 {               }) {:cnt "cnt", :aad "aad"} "-AKM, +AAD")
        (is= (dec (enc ba-cnt kc1 {:ba-aad ba-aad
                                   :ba-akm ba-akm}) kc1 {:ba-akm ba-akm }) {:cnt "cnt", :aad "aad"} "+AKM, +AAD")

        (is= (dec (enc ba-cnt kc1 {              }) kc2 {               }) {:err "Unexpected HMAC" #_"Tag mismatch"} "Bad key")
        (is= (dec (enc ba-cnt kc1 {:ba-akm ba-akm}) kc1 {:ba-akm ba-!akm}) {:err "Unexpected HMAC" #_"Tag mismatch"} "Bad AKM")

        (is= (pd  (enc ba-cnt kc1 {              })) {:kind :encrypted-with-symmetric-key, :key-id "a"            } "Public data")
        (is= (pd  (enc ba-cnt kc1 {:ba-aad ba-aad})) {:kind :encrypted-with-symmetric-key, :key-id "a", :aad "aad"} "Public data +AAD")

        (is= (dec (enc ba-cnt kc1 {:backup-key master-kc               }) kc1 {                     }) {:cnt "cnt"} "+Backup, use primary, -AKM, -AAD")
        (is= (dec (enc ba-cnt kc1 {:backup-key master-kc :ba-akm ba-akm}) kc1 {:ba-akm ba-akm       }) {:cnt "cnt"} "+Backup, use primary, +AKM, -AAD")
        (is= (dec (enc ba-cnt kc1 {:backup-key master-kc               }) nil {:backup-key master-kc}) {:cnt "cnt"} "+Backup, use backup,  -AKM, -AAD")
        (is= (dec (enc ba-cnt kc1 {:backup-key master-kc :ba-akm ba-akm}) nil {:backup-key master-kc}) {:cnt "cnt"} "+Backup, use backup,  +AKM, -AAD")

        (is (:passed? (combinatorial-roundtrip-tests! "roundtrip with symmetric key" :rand-bytes enc dec kc1 kc1 kc2)))]))

   (testing "Encryption with 1 keypair"
     (let [enc (fn [ba-cnt key-pub opts] (tempel/encrypt-with-1-keypair ba-cnt key-pub (merge {}               opts)))
           dec (fn [ba-enc key-prv opts] (tempel/decrypt-with-1-keypair ba-enc key-prv (merge {:return :_test} opts)))
           kc1 (-> (keys/keychain) (keys/keychain-add-asymmetric-keypair :rsa-1024 {:key-id "a"}))
           kc2 (-> (keys/keychain) (keys/keychain-add-asymmetric-keypair :rsa-1024 {:key-id "a"}))]

       [(every? boolean
          (for [cnt ["short" (apply str (repeat 128 "x"))]]
            (let [ba-cnt (as-ba cnt)]
              [(is= (dec (enc ba-cnt kc1 {              }) kc1 {               }) {:cnt cnt            } "-AKM, -AAD")
               (is= (dec (enc ba-cnt kc1 {:ba-akm ba-akm}) kc1 {:ba-akm ba-akm }) {:cnt cnt            } "+AKM, -AAD")
               (is= (dec (enc ba-cnt kc1 {:ba-aad ba-aad}) kc1 {               }) {:cnt cnt, :aad "aad"} "-AKM, +AAD")
               (is= (dec (enc ba-cnt kc1 {:ba-aad ba-aad
                                          :ba-akm ba-akm}) kc1 {:ba-akm ba-akm }) {:cnt cnt, :aad "aad"} "+AKM, +AAD")

               (is= (dec (enc ba-cnt kc1 {              }) kc2 {               }) {:err #{"Decryption error" "Message is larger than modulus" "Padding error in decryption"}} "Bad key")
               (is= (dec (enc ba-cnt kc1 {:ba-akm ba-akm}) kc1 {:ba-akm ba-!akm}) {:err "Unexpected HMAC" #_"Tag mismatch"}                                                   "Bad AKM")

               (is= (pd  (enc ba-cnt kc1 {              })) {:kind :encrypted-with-1-keypair, :key-algo :rsa-1024, :key-id "a"            } "Public data")
               (is= (pd  (enc ba-cnt kc1 {:ba-aad ba-aad})) {:kind :encrypted-with-1-keypair, :key-algo :rsa-1024, :key-id "a", :aad "aad"} "Public data +AAD")

               (is= (dec (enc ba-cnt kc1 {:backup-key master-kc               }) kc1 {                     }) {:cnt cnt} "+Backup, use primary, -AKM, -AAD")
               (is= (dec (enc ba-cnt kc1 {:backup-key master-kc :ba-akm ba-akm}) kc1 {:ba-akm ba-akm       }) {:cnt cnt} "+Backup, use primary, +AKM, -AAD")
               (is= (dec (enc ba-cnt kc1 {:backup-key master-kc               }) nil {:backup-key master-kc}) {:cnt cnt} "+Backup, use backup,  -AKM, -AAD")
               (is= (dec (enc ba-cnt kc1 {:backup-key master-kc :ba-akm ba-akm}) nil {:backup-key master-kc}) {:cnt cnt} "+Backup, use backup,  +AKM, -AAD")])))

        (is (:passed? (combinatorial-roundtrip-tests! "roundtrip with 1 keypair" :rand-bytes enc dec kc1 kc1 kc2)))]))

   (testing "Encryption with 2 keypairs"
     (let [enc (fn [ba-cnt [key-pub key-prv] opts] (tempel/encrypt-with-2-keypairs ba-cnt key-pub key-prv (merge {}               opts)))
           dec (fn [ba-enc [key-prv key-pub] opts] (tempel/decrypt-with-2-keypairs ba-enc key-prv key-pub (merge {:return :_test} opts)))
           kc1 (-> (keys/keychain) (keys/keychain-add-asymmetric-keypair :dh-3072 {:key-id "r"}))
           kc2 (-> (keys/keychain) (keys/keychain-add-asymmetric-keypair :dh-3072 {:key-id "s"}))
           kc3 (-> (keys/keychain) (keys/keychain-add-asymmetric-keypair :dh-3072 {:key-id "s"}))]

       [(is= (dec (enc ba-cnt [kc1 kc2] {              }) [kc1 kc2] {               }) {:cnt "cnt"}             "-AKM, -AAD")
        (is= (dec (enc ba-cnt [kc1 kc2] {:ba-akm ba-akm}) [kc1 kc2] {:ba-akm ba-akm }) {:cnt "cnt"}             "+AKM, -AAD")
        (is= (dec (enc ba-cnt [kc1 kc2] {:ba-aad ba-aad}) [kc1 kc2] {               }) {:cnt "cnt", :aad "aad"} "-AKM, +AAD")
        (is= (dec (enc ba-cnt [kc1 kc2] {:ba-aad ba-aad
                                         :ba-akm ba-akm}) [kc1 kc2] {:ba-akm ba-akm }) {:cnt "cnt", :aad "aad"} "+AKM, +AAD")

        (is= (dec (enc ba-cnt [kc1 kc2] {              }) [kc1 kc3] {               }) {:err "Unexpected HMAC" #_"Tag mismatch"} "Bad key")
        (is= (dec (enc ba-cnt [kc1 kc2] {:ba-akm ba-akm}) [kc1 kc2] {:ba-akm ba-!akm}) {:err "Unexpected HMAC" #_"Tag mismatch"} "Bad AKM")

        (is= (pd  (enc ba-cnt [kc1 kc2] {              })) {:kind :encrypted-with-2-keypairs, :key-algo :dh-3072, :receiver-key-id "r", :sender-key-id "s"            } "Public data")
        (is= (pd  (enc ba-cnt [kc1 kc2] {:ba-aad ba-aad})) {:kind :encrypted-with-2-keypairs, :key-algo :dh-3072, :receiver-key-id "r", :sender-key-id "s", :aad "aad"} "Public data +AAD")

        (is= (dec (enc ba-cnt [kc1 kc2] {:backup-key master-kc               }) [kc1 kc2] {                     }) {:cnt "cnt"} "+Backup, use primary, -AKM, -AAD")
        (is= (dec (enc ba-cnt [kc1 kc2] {:backup-key master-kc :ba-akm ba-akm}) [kc1 kc2] {:ba-akm ba-akm       }) {:cnt "cnt"} "+Backup, use primary, +AKM, -AAD")
        (is= (dec (enc ba-cnt [kc1 kc2] {:backup-key master-kc               }) nil       {:backup-key master-kc}) {:cnt "cnt"} "+Backup, use backup,  -AKM, -AAD")
        (is= (dec (enc ba-cnt [kc1 kc2] {:backup-key master-kc :ba-akm ba-akm}) nil       {:backup-key master-kc}) {:cnt "cnt"} "+Backup, use backup,  +AKM, -AAD")

        (is (:passed? (combinatorial-roundtrip-tests! "roundtrip with 2 keypairs" :rand-bytes enc dec [kc1 kc2] [kc1 kc2] [kc1 kc3])))]))

   (testing "Encrypted keychains"
     (let [enc (fn [kc  key-opts opts] (keys/keychain-encrypt kc  (merge {}               key-opts opts)))
           dec (fn [ekc key-opts opts] (keys/keychain-decrypt ekc (merge {:return :_test} key-opts opts)))
           kc  (keys/keychain {:symmetric-keys      [:random :random]
                               :asymmetric-keypairs [:rsa-1024 :dh-1024 :ec-secp256r1]})]

       [(is= (dec (enc kc {:password "pwd"} {              }) {:password "pwd"} {              }) {:kc kc}             "-AKM, -AAD")
        (is= (dec (enc kc {:password "pwd"} {:ba-akm ba-akm}) {:password "pwd"} {:ba-akm ba-akm}) {:kc kc}             "+AKM, -AAD")
        (is= (dec (enc kc {:password "pwd"} {:ba-aad ba-aad}) {:password "pwd"} {              }) {:kc kc, :aad "aad"} "-AKM, +AAD")
        (is= (dec (enc kc {:password "pwd"} {:ba-aad ba-aad
                                             :ba-akm ba-akm}) {:password "pwd"} {:ba-akm ba-akm}) {:kc kc, :aad "aad"} "+AKM, +AAD")

        (is= (dec (enc kc {:password "pwd"} {              }) {:password "!pwd"} {               }) nil "Bad pwd")
        (is= (dec (enc kc {:password "pwd"} {:ba-akm ba-akm}) {:password  "pwd"} {:ba-akm ba-!akm}) nil "Bad AKM")

        (is= (pd  (enc kc {:password "pwd"} {              })) {:kind :encrypted-keychain            } "Public data")
        (is= (pd  (enc kc {:password "pwd"} {:ba-aad ba-aad})) {:kind :encrypted-keychain, :aad "aad"} "Public data +AAD")

        ;; Embedded (private user) content
        (is=      (dec (enc kc {:password "pwd"} {:ba-content (as-ba "cnt")}) {:password "pwd"} {}) {:kc kc, :cnt "cnt"} "Private content")
        (let [pd1 (pd  (enc kc {:password "pwd"} {:ba-content (as-ba "cnt")}))
              pd2 (pd  (enc kc {:password "pwd"} {}))]
          (is (= pd1 pd2) "Private content not in public data"))

        (is= (dec (enc kc {:password "pwd"} {:backup-key master-kc               }) {:password "pwd"} {                     }) {:kc kc} "+Backup, use primary, -AKM, -AAD")
        (is= (dec (enc kc {:password "pwd"} {:backup-key master-kc :ba-akm ba-akm}) {:password "pwd"} {:ba-akm ba-akm       }) {:kc kc} "+Backup, use primary, +AKM, -AAD")
        (is= (dec (enc kc {:password "pwd"} {:backup-key master-kc               }) {               } {:backup-key master-kc}) {:kc kc} "+Backup, use backup,  -AKM, -AAD")
        (is= (dec (enc kc {:password "pwd"} {:backup-key master-kc :ba-akm ba-akm}) {               } {:backup-key master-kc}) {:kc kc} "+Backup, use backup,  +AKM, -AAD")

        (let [ba-key   (impl/rand-ba 32)
              ba-!key  (impl/rand-ba 32)

              key-sym  (keys/keychain {:only? true :symmetric-keys [:random]})
              !key-sym (keys/keychain {:only? true :symmetric-keys [:random]})]

          (binding [tempel/*config* (merge tempel/*config* {:pbkdf-nwf :ref-10-msecs})]
            (every? :passed?
              (for [[key-opts !key-opts]
                    [[{:password  "pwd"} {:password  "!pwd"}]
                     [{:key-sym  ba-key} {:key-sym  ba-!key}]
                     [{:key-sym key-sym} {:key-sym !key-sym}]]]

                (combinatorial-roundtrip-tests! "keychain roundtrip" kc enc dec key-opts key-opts !key-opts)))))]))

   (testing "Signing"
     (let [sig (fn [ba-cnt    key-prv opts] (tempel/sign   ba-cnt    key-prv (merge {}               opts)))
           ver (fn [ba-signed key-pub opts] (tempel/signed ba-signed key-pub (merge {:return :_test} opts)))
           kc1 (-> (keys/keychain) (keys/keychain-add-asymmetric-keypair :rsa-3072 {:key-id "a"}))
           kc2 (-> (keys/keychain) (keys/keychain-add-asymmetric-keypair :rsa-3072 {:key-id "a"}))]

       [(is= (ver (sig ba-cnt kc1 {              })  kc1 {               }) {}           "-AKM, -AAD")
        (is= (ver (sig ba-cnt kc1 {:ba-akm ba-akm})  kc1 {:ba-akm ba-akm }) {}           "+AKM, -AAD")
        (is= (ver (sig ba-cnt kc1 {:ba-aad ba-aad})  kc1 {               }) {:aad "aad"} "-AKM, +AAD")
        (is= (ver (sig ba-cnt kc1 {:ba-aad ba-aad
                                   :ba-akm ba-akm})  kc1 {:ba-akm ba-akm }) {:aad "aad"} "+AKM, +AAD")

        (is= (ver (sig ba-cnt kc1 {              })  kc2 {               }) nil "Bad key")
        (is= (ver (sig ba-cnt kc1 {:ba-akm ba-akm})  kc1 {:ba-akm ba-!akm}) nil "Bad AKM")

        (is= (pd  (sig ba-cnt kc1 {              })) {:kind :signed, :key-algo :rsa-3072, :key-id "a"            } "Public data")
        (is= (pd  (sig ba-cnt kc1 {:ba-aad ba-aad})) {:kind :signed, :key-algo :rsa-3072, :key-id "a", :aad "aad"} "Public data +AAD")

        ;; Embedded (signed) content
        (is= (ver (sig ba-cnt kc1 {:embed-content? true }) kc1 {                   }) {:cnt "cnt"} "Embedded content")
        (is= (ver (sig ba-cnt kc1 {:embed-content? false}) kc1 {:ba-content ba-cnt }) {:cnt "cnt"} "Provided content")
        (is= (pd  (sig ba-cnt kc1 {:embed-content? true }))                           {:cnt "cnt"} "Embedded content in public data")
        (is= (ver (sig ba-cnt kc1 {:embed-content? false}) kc1 {:ba-content ba-!cnt}) nil          "Provided content bad")
        (is= (ver (sig ba-cnt kc1 {:embed-content? false}) kc1 {:ba-content nil})     nil          "Provided content missing")

        (with-rand-data (mbytes 4) 256
          (fn [ba-cnt ?ba-aad]
            (let [ba-signed (sig ba-cnt    kc1 {:ba-aad ?ba-aad})
                  verified  (ver ba-signed kc1 {:return :map})]

              [(is (bytes/?ba=  ba-cnt (:ba-content verified)))
               (is (bytes/?ba= ?ba-aad (:ba-aad     verified)))])))]))])

(deftest _core-keychains
  [(testing "Encryption with symmetric key, no embedded key ids"
     (let [kc1-prv (keys/keychain {:only? true, :symmetric-keys [:random :random :random :random]})
           kc1-pub (:keychain (pd (keys/keychain-encrypt kc1-prv {:password "pwd"})))
           kc2-prv (keys/keychain-remove kc1-prv "1")
           ck1-sym (get-in @kc1-prv ["1" :key-sym]) ; Manually select lowest-priority key

           ba-enc-named   (tempel/encrypt-with-symmetric-key (as-ba "cnt") ck1-sym {:embed-key-ids? true})
           ba-enc-unnamed (tempel/encrypt-with-symmetric-key (as-ba "cnt") ck1-sym {:embed-key-ids? false})]

       [(is  (= (kci kc1-prv) {:secret? true, :n-sym 4}))
        (is  (= (kci kc1-pub) {:secret? false}))
        (is  (= (get (pd ba-enc-named)   :key-id) "1"))
        (is  (= (get (pd ba-enc-unnamed) :key-id) nil))

        (is= (tempel/decrypt-with-symmetric-key ba-enc-unnamed ck1-sym {:return :_test}) {:cnt "cnt"}               "Try 1 -> succeed: exact key given")
        (is= (tempel/decrypt-with-symmetric-key ba-enc-unnamed kc1-prv {:return :_test}) {:cnt "cnt"}               "Try 4 -> succeed: must try all")
        (is= (tempel/decrypt-with-symmetric-key ba-enc-unnamed kc1-pub {:return :_test}) {:err {:key-type :sym}}    "Try 0 -> fail: no sym keys")
        (is= (tempel/decrypt-with-symmetric-key ba-enc-unnamed kc2-prv {:return :_test}) {:err {:num-keys-tried 3}} "Try 3 -> fail: relevant key removed")

        (is= (tempel/decrypt-with-symmetric-key ba-enc-named   ck1-sym {:return :_test}) {:cnt "cnt"}         "Try 1 -> succeed: exact key given")
        (is= (tempel/decrypt-with-symmetric-key ba-enc-named   kc1-prv {:return :_test}) {:cnt "cnt"}         "Try 1 -> succeed: exact key identified")
        (is= (tempel/decrypt-with-symmetric-key ba-enc-named   kc1-pub {:return :_test}) {:err {:key-id "1"}} "Try 0 -> fail: no sym keys")
        (is= (tempel/decrypt-with-symmetric-key ba-enc-named   kc2-prv {:return :_test}) {:err {:key-id "1"}} "Try 0 -> fail: exact key missing")]))

   (testing "Encryption with 1 keypair, no embedded key ids"
     (let [kc1-prv (keys/keychain {:only? true, :asymmetric-keypairs [:rsa-1024 :rsa-1024 :rsa-1024 :rsa-1024]})
           kc1-pub (:keychain (pd (keys/keychain-encrypt kc1-prv {:password "pwd"})))
           kc2-prv (keys/keychain-remove kc1-prv "1" {:keep-private? false})

           ck1-pub (get-in @kc1-pub ["1" :key-pub]) ; Manually select lowest-priority key
           ck1-prv (get-in @kc1-prv ["1" :key-prv])

           ba-enc-named   (tempel/encrypt-with-1-keypair (as-ba "cnt") ck1-pub {:embed-key-ids? true})
           ba-enc-unnamed (tempel/encrypt-with-1-keypair (as-ba "cnt") ck1-pub {:embed-key-ids? false})]

       [(is  (= (kci kc1-prv) {:secret? true, :n-prv 4, :n-pub 4}))
        (is  (= (kci kc1-pub) {:secret? false,          :n-pub 4}))
        (is  (= (get (pd ba-enc-named)   :key-id) "1"))
        (is  (= (get (pd ba-enc-unnamed) :key-id) nil))

        (is= (tempel/decrypt-with-1-keypair ba-enc-unnamed ck1-prv {:return :_test}) {:cnt "cnt"}               "Try 1 -> succeed: exact key given")
        (is= (tempel/decrypt-with-1-keypair ba-enc-unnamed kc1-prv {:return :_test}) {:cnt "cnt"}               "Try 4 -> succeed: must try all")
        (is= (tempel/decrypt-with-1-keypair ba-enc-unnamed kc1-pub {:return :_test}) {:err {:key-type :prv}}    "Try 0 -> fail: no private keys")
        (is= (tempel/decrypt-with-1-keypair ba-enc-unnamed kc2-prv {:return :_test}) {:err {:num-keys-tried 3}} "Try 3 -> fail: relevant key removed")

        (is= (tempel/decrypt-with-1-keypair ba-enc-named   ck1-prv {:return :_test}) {:cnt "cnt"}         "Try 1 -> succeed: exact key given")
        (is= (tempel/decrypt-with-1-keypair ba-enc-named   kc1-prv {:return :_test}) {:cnt "cnt"}         "Try 1 -> succeed: exact key identified")
        (is= (tempel/decrypt-with-1-keypair ba-enc-named   kc1-pub {:return :_test}) {:err {:key-id "1"}} "Try 0 -> fail: no private keys")
        (is= (tempel/decrypt-with-1-keypair ba-enc-named   kc2-prv {:return :_test}) {:err {:key-id "1"}} "Try 0 -> fail: exact key missing")]))])
