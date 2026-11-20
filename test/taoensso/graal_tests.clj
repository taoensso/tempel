(ns taoensso.graal-tests
  (:require [taoensso.tempel :as tempel])
  (:gen-class))

(defn -main [& _]
  (let [content (byte-array [1 2 3])
        receiver (tempel/keypair-create :x25519)
        signer   (tempel/keypair-create :ed25519)]
    (assert (java.util.Arrays/equals content
              ^bytes (tempel/decrypt-with-1-keypair
                       (tempel/encrypt-with-1-keypair content receiver) receiver))
      "X25519 decryption failed")
    (assert (java.util.Arrays/equals content
              ^bytes (tempel/signed (tempel/sign content signer) signer {:return :ba-content}))
      "Ed25519 verification failed")))
