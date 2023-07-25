(ns taoensso.tempel-tests
  (:require
   [clojure.test                     :as test :refer [deftest testing is]]
   ;; [clojure.test.check            :as tc]
   ;; [clojure.test.check.generators :as tc-gens]
   ;; [clojure.test.check.properties :as tc-props]
   [taoensso.encore :as enc]
   [taoensso.tempel :as tempel]))

(comment
  (remove-ns      'taoensso.tempel-tests)
  (test/run-tests 'taoensso.tempel-tests))

;;;;

(deftest _test (is (= 1 1)))
